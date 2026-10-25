package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

// Формат хеша пароля: pbkdf2-sha256:<итерации>:<соль>:<хеш>, соль и хеш
// в base64url без «=». Разделитель «:» выбран, чтобы строку можно было
// без экранирования положить в .env (там «$» иногда раскрывается).
const (
	hashPrefix     = "pbkdf2-sha256"
	hashIterations = 600_000 // рекомендация OWASP для PBKDF2-HMAC-SHA256
	hashSaltLen    = 16
	hashKeyLen     = 32
)

// HashPassword вычисляет хеш пароля для SSG_AUTH_PASSWORD_HASH.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", i18n.Errorf("err.password_short")
	}
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, hashIterations, hashKeyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s:%d:%s:%s", hashPrefix, hashIterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword сравнивает пароль с хешем за постоянное время.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 10_000 || iter > 10_000_000 {
		return false
	}
	enc := base64.RawURLEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidHash проверяет формат строки хеша (при запуске).
func ValidHash(encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(parts[2])
	_, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	return err == nil && err2 == nil
}

// session — серверная сессия. Хранится в памяти: после перезапуска
// службы нужно войти заново, зато токены нигде не лежат на диске.
type session struct {
	csrf     string
	expires  time.Time // абсолютный срок (SSG_SESSION_TTL)
	lastSeen time.Time // последний запрос — для тайм-аута простоя
}

// sessionIdle — сессия без запросов дольше этого закрывается, даже если
// SSG_SESSION_TTL ещё не истёк: забытая открытая вкладка на чужом
// компьютере не остаётся входом в панель на 12 часов. Открытая панель
// обновляет данные сама, поэтому рабочую вкладку тайм-аут не закрывает.
const sessionIdle = 2 * time.Hour

type sessionStore struct {
	mu   sync.Mutex
	ttl  time.Duration
	idle time.Duration
	data map[string]session
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{ttl: ttl, idle: min(sessionIdle, ttl), data: map[string]session{}}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand не должен отказывать; без него нельзя продолжать безопасно
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// create создаёт сессию и возвращает её токен и CSRF-токен.
func (s *sessionStore) create(now time.Time) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Заодно чистим просроченные.
	for k, v := range s.data {
		if s.expired(v, now) {
			delete(s.data, k)
		}
	}
	tok, csrf := randomToken(), randomToken()
	s.data[tok] = session{csrf: csrf, expires: now.Add(s.ttl), lastSeen: now}
	return tok, csrf
}

func (s *sessionStore) get(tok string, now time.Time) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[tok]
	if !ok || s.expired(v, now) {
		delete(s.data, tok)
		return session{}, false
	}
	v.lastSeen = now
	s.data[tok] = v
	return v, true
}

func (s *sessionStore) expired(v session, now time.Time) bool {
	return now.After(v.expires) || now.Sub(v.lastSeen) > s.idle
}

func (s *sessionStore) delete(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, tok)
}

// loginLimiter ограничивает число попыток входа с одного адреса: не
// более maxFails за окно window. Попытка учитывается до проверки пароля
// (begin), а не после: PBKDF2 идёт сотни миллисекунд, и при проверке
// «заблокирован?» → пароль → «записать неудачу» все параллельные запросы
// успевали пройти первую проверку — сотня запросов давала сотню попыток.
type loginLimiter struct {
	mu       sync.Mutex
	maxFails int
	window   time.Duration
	fails    map[string][]time.Time
	// verify ограничивает число одновременных проверок PBKDF2: поток
	// запросов не займёт весь процессор и не задержит сканирование.
	verify chan struct{}
	// lastSweep — когда таблица целиком чистилась от устаревших записей.
	// prune чистит только адрес текущего запроса, и записи адресов, с
	// которых больше не приходили, копились бы бесконечно.
	lastSweep time.Time
}

// maxParallelVerify — сколько паролей проверяется одновременно.
const maxParallelVerify = 2

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{maxFails: 5, window: 15 * time.Minute, fails: map[string][]time.Time{},
		verify: make(chan struct{}, maxParallelVerify)}
}

// begin атомарно проверяет лимит и сразу учитывает попытку. false —
// адрес заблокирован. При успешном входе попытки сбрасывает reset.
func (l *loginLimiter) begin(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) > l.window {
		for k := range l.fails {
			l.prune(k, now)
		}
		l.lastSweep = now
	}
	list := l.prune(key, now)
	if len(list) >= l.maxFails {
		return false
	}
	l.fails[key] = append(list, now)
	return true
}

// acquire занимает слот проверки пароля, ожидая не дольше wait.
func (l *loginLimiter) acquire(wait time.Duration) bool {
	select {
	case l.verify <- struct{}{}:
		return true
	case <-time.After(wait):
		return false
	}
}

func (l *loginLimiter) release() { <-l.verify }

func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	list := l.fails[ip]
	i := 0
	for _, t := range list {
		if now.Sub(t) < l.window {
			list[i] = t
			i++
		}
	}
	list = list[:i]
	if len(list) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = list
	}
	return list
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
