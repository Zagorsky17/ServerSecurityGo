package tui

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/web"
)

// demoScanner создаёт сканер над демонстрационным деревом.
func demoScanner(t *testing.T) *scanner.Scanner {
	sc, _ := demoEnv(t)
	return sc
}

// demoEnv — сканер и аудит над одним демо-деревом.
func demoEnv(t *testing.T) (*scanner.Scanner, *audit.Runner) {
	t.Helper()
	return demoEnvTree(t, fakeproc.Demo(time.Now()))
}

func demoEnvTree(t *testing.T, tree *fakeproc.Tree) (*scanner.Scanner, *audit.Runner) {
	t.Helper()
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: detect.DefaultConfig(), History: hist,
		Interval: time.Hour, Logger: quiet, Hostname: "demo-host", Demo: true})
	ar := audit.NewRunner(audit.RunnerOptions{HostRoot: hostRoot, RootUID: os.Getuid(), Interval: time.Hour, Record: hist.RecordAudit, Logger: quiet})
	return sc, ar
}

// newTestApp — интерфейс на демо-данных без настоящего терминала.
func newTestApp(t *testing.T, w, h int) (*App, *bytes.Buffer) {
	return newTestAppLang(t, w, h, i18n.RU)
}

func newTestAppLang(t *testing.T, w, h int, lang i18n.Lang) (*App, *bytes.Buffer) {
	t.Helper()
	sc, ar := demoEnv(t)
	src, err := NewLocalSource(sc, ar, "test", true, i18n.T("tui.source_demo"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Close)
	out := &bytes.Buffer{}
	a := New(Options{Source: src, Out: out, Lang: lang})
	a.w, a.h = w, h
	a.load()
	return a, out
}

func screen(a *App) string {
	a.render()
	return a.scr.String()
}

func press(a *App, keys ...Key) {
	for _, k := range keys {
		a.handleKey(k)
	}
}

func r(c rune) Key { return Key{Kind: KeyRune, Rune: c} }

func TestRenderPanels(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	s := screen(a)
	for _, want := range []string{"[1] Сводка", "[2] Подозрительные", "[3] Процессы", "[4] Сеть", "[5] Порты", "[6] Настройки", "[7] fail2ban", "[8] История", "[9] Система",
		"demo-host", "CRIT 4", "kworkerds", "CRITICAL", "Оценка риска", "q выход"} {
		if !strings.Contains(s, want) {
			t.Errorf("на экране нет %q\n%s", want, s)
		}
	}
	// Справа — карточка первого подозрительного процесса.
	if !strings.Contains(s, "Признаки") || !strings.Contains(s, "PID 3301") {
		t.Errorf("нет карточки процесса:\n%s", s)
	}
	// В выводе только экран без лишних управляющих последовательностей,
	// кроме SGR и позиционирования.
	if err := a.scr.Flush(io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestNavigation(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	first := a.susp[0].Key
	press(a, Key{Kind: KeyDown})
	if a.lists[pSusp].cursor != 1 || a.susp[1].Key == first {
		t.Fatalf("курсор не сдвинулся: %d", a.lists[pSusp].cursor)
	}
	press(a, r('3'))
	if a.focus != pProcs || a.expanded != pProcs {
		t.Errorf("фокус %d", a.focus)
	}
	press(a, Key{Kind: KeyTab})
	if a.focus != pNet {
		t.Errorf("Tab: фокус %d", a.focus)
	}
	press(a, Key{Kind: KeyEnter})
	if !a.inMain {
		t.Error("Enter должен переводить фокус в подробности")
	}
	press(a, Key{Kind: KeyEsc})
	if a.inMain {
		t.Error("Esc должен возвращать к списку")
	}
	press(a, r('?'))
	if s := screen(a); !a.help || !strings.Contains(s, "Клавиши") {
		t.Error("справка не открылась")
	}
	press(a, Key{Kind: KeyEsc})
	if a.help {
		t.Error("справка не закрылась")
	}
	if !a.handleKey(r('q')) {
		t.Error("q должна завершать интерфейс")
	}
}

func TestFilterSortTree(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	press(a, r('3'), r('/'))
	for _, c := range "nginx" {
		press(a, r(c))
	}
	press(a, Key{Kind: KeyEnter})
	if len(a.procs) != 2 {
		t.Fatalf("фильтр nginx: %d процессов", len(a.procs))
	}
	if s := screen(a); !strings.Contains(s, "/nginx") {
		t.Error("фильтр не показан в заголовке")
	}
	press(a, Key{Kind: KeyEsc})
	if a.lists[pProcs].filter != "" {
		t.Error("Esc не сбросил фильтр")
	}
	press(a, r('s')) // CPU
	if a.sortMode != 1 || a.procs[0].CPUPercent < a.procs[len(a.procs)-1].CPUPercent {
		t.Errorf("сортировка по CPU: режим %d", a.sortMode)
	}
	press(a, r('t'))
	s := screen(a)
	if !a.treeMode || !strings.Contains(s, "└─") || !strings.Contains(s, "дерево") {
		t.Errorf("дерево не построено:\n%s", s)
	}
	// В дереве bash (3202) — потомок sh (3201), который потомок nginx worker.
	idx := map[int]int{}
	for i, p := range a.procs {
		idx[p.PID] = i
	}
	if !(idx[721] < idx[3201] && idx[3201] < idx[3202]) {
		t.Errorf("порядок дерева неверный: %v", idx)
	}
}

func TestPanelsDetails(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	press(a, r('4'))
	if s := screen(a); !strings.Contains(s, "Сокет") || !strings.Contains(s, "LISTEN") {
		t.Errorf("панель сети:\n%s", s)
	}
	press(a, r('9'))
	if s := screen(a); !strings.Contains(s, "ld.so.preload") {
		t.Errorf("панель системы:\n%s", s)
	}
	press(a, r('8'))
	if s := screen(a); !strings.Contains(s, "Начало") && !strings.Contains(s, "Признак") && !strings.Contains(s, "Настройки безопасности: «") {
		t.Errorf("панель истории:\n%s", s)
	}
	// Порты: самый опасный — MongoDB, опубликованный Docker в обход ufw.
	press(a, r('5'))
	if s := screen(a); !strings.Contains(s, "Порт 0.0.0.0:27017") || !strings.Contains(s, "MongoDB") || !strings.Contains(s, "в обход ufw") {
		t.Errorf("панель портов:\n%s", s)
	}
	press(a, r('1'))
	if s := screen(a); !strings.Contains(s, "Обзор") || !strings.Contains(s, "Быстрый старт") {
		t.Errorf("обзор:\n%s", s)
	}
}

func TestNarrowAndZoom(t *testing.T) {
	a, _ := newTestApp(t, 70, 24)
	s := screen(a)
	if !strings.Contains(s, "[2] Подозрительные") || strings.Contains(s, "Оценка риска") {
		t.Errorf("в узком окне должен быть виден только список:\n%s", s)
	}
	press(a, Key{Kind: KeyEnter})
	if s := screen(a); !strings.Contains(s, "Оценка риска") {
		t.Errorf("в узком окне Enter должен показать подробности:\n%s", s)
	}
	// Совсем маленькое окно не должно паниковать.
	a.w, a.h = 10, 5
	screen(a)
}

func TestCopyOSC52(t *testing.T) {
	a, out := newTestApp(t, 160, 45)
	press(a, r('y'))
	if !strings.Contains(out.String(), "\x1b]52;c;") {
		t.Error("нет OSC 52 при копировании")
	}
}

func TestMouse(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	screen(a)
	pr := a.rects[pProcs]
	// Клик по третьей строке панели «Процессы» (после рамки и заголовка).
	press(a, Key{Kind: KeyMouse, Button: 0, X: pr.x + 3, Y: pr.y + 1, Press: true})
	if a.focus != pProcs {
		t.Fatalf("клик не перевёл фокус: %d", a.focus)
	}
	screen(a)
	pr = a.rects[pProcs]
	press(a, Key{Kind: KeyMouse, Button: 0, X: pr.x + 3, Y: pr.y + 1 + a.headers[pProcs] + 2, Press: true})
	if a.lists[pProcs].cursor != 2 {
		t.Errorf("клик по строке: курсор %d", a.lists[pProcs].cursor)
	}
	press(a, Key{Kind: KeyMouse, Button: 65, X: pr.x + 3, Y: pr.y + 3, Press: true})
	if a.lists[pProcs].cursor != 5 {
		t.Errorf("колесо: курсор %d", a.lists[pProcs].cursor)
	}
}

func TestParseKeys(t *testing.T) {
	ks := parseKeys([]byte("\x1b[A\x1b[B\x1bOC\x1b[D\x1b[5~\x1b[6~\x1b[Z\rq\x03\x1b[<0;10;5M\x1b[<65;3;4M\x7fж"))
	want := []KeyKind{KeyUp, KeyDown, KeyRight, KeyLeft, KeyPgUp, KeyPgDn, KeyBackTab, KeyEnter, KeyRune, KeyCtrlC, KeyMouse, KeyMouse, KeyBackspace, KeyRune}
	if len(ks) != len(want) {
		t.Fatalf("клавиш %d: %+v", len(ks), ks)
	}
	for i, k := range ks {
		if k.Kind != want[i] {
			t.Errorf("%d: %v, ожидалось %v", i, k.Kind, want[i])
		}
	}
	if ks[10].X != 9 || ks[10].Y != 4 || ks[11].Button != 65 || ks[13].Rune != 'ж' {
		t.Errorf("мышь/символ: %+v %+v %+v", ks[10], ks[11], ks[13])
	}
	if k := parseKeys([]byte{0x1b}); len(k) != 1 || k[0].Kind != KeyEsc {
		t.Errorf("одиночный Esc: %+v", k)
	}
}

func TestEscapeInjection(t *testing.T) {
	// Имя процесса с ESC-последовательностью не должно попасть в терминал.
	s := newScreen(40, 2)
	s.Text(0, 0, 40, "evil\x1b]52;c;AAAA\x07\x1b[2J", stNormal)
	var out bytes.Buffer
	_ = s.Flush(&out)
	if strings.Contains(out.String(), "\x1b]52") || strings.Contains(out.String(), "\x1b[2J") {
		t.Errorf("управляющая последовательность прошла: %q", out.String())
	}
	if got := sanitize("a\x1bb\tc"); got != "a�b c" {
		t.Errorf("sanitize: %q", got)
	}
}

func TestTextHelpers(t *testing.T) {
	if got := fit("процесс", 5); got != "проц…" {
		t.Errorf("fit: %q", got)
	}
	if got := fit("ab", 4); got != "ab  " {
		t.Errorf("fit pad: %q", got)
	}
	if strWidth("日本") != 4 || strWidth("ёж") != 2 {
		t.Error("ширина символов")
	}
	lines := wrap("/very/long/path/without/spaces/at/all and words", 10)
	for _, l := range lines {
		if strWidth(l) > 10 {
			t.Errorf("строка шире 10: %q", l)
		}
	}
}

// TestRemoteSourceOldService: терминал новее службы — у службы нет
// /api/exposure (404). Остальные данные загружаются, панель портов пуста.
func TestRemoteSourceOldService(t *testing.T) {
	sc := demoScanner(t)
	if _, err := sc.ScanOnce(); err != nil {
		t.Fatal(err)
	}
	srv := web.New(web.Options{Scanner: sc, Version: "old", ListenAddr: "127.0.0.1:8090", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	local := srv.LocalHandler()
	old := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/exposure" || r.URL.Path == "/api/audit" || r.URL.Path == "/api/fail2ban" {
			http.NotFound(w, r)
			return
		}
		local.ServeHTTP(w, r)
	})
	dir, err := makeShortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "o.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: old}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })

	rs, err := DialSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	d, err := rs.Fetch()
	if err != nil || d.Exposure != nil || d.Audit != nil || d.Fail2ban != nil || len(d.Procs) == 0 {
		t.Fatalf("Fetch у старой службы: %v %+v %+v", err, d.Exposure, d.Audit)
	}
	a := New(Options{Source: rs, Out: io.Discard, Lang: i18n.RU})
	a.w, a.h = 160, 45
	a.load()
	press(a, r('5'))
	if s := screen(a); !strings.Contains(s, "[5] Порты (0)") {
		t.Errorf("панель портов:\n%s", s)
	}
}

// TestRemoteSource проверяет работу через Unix-сокет службы: тот же
// обработчик, что у serve (LocalHandler), без пароля и проверки Host.
func TestRemoteSource(t *testing.T) {
	sc := demoScanner(t)
	if _, err := sc.ScanOnce(); err != nil {
		t.Fatal(err)
	}
	hash, _ := web.HashPassword("correct horse battery")
	srv := web.New(web.Options{Scanner: sc, Version: "test", ListenAddr: "127.0.0.1:8090", PasswordHash: hash,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	// Короткий путь: у Unix-сокетов ограничение ~104 байта (macOS).
	dir, err := makeShortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.LocalHandler()}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })

	rs, err := DialSocket(path)
	if err != nil {
		t.Fatalf("подключение к сокету: %v", err)
	}
	d, err := rs.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(d.Procs) == 0 || len(d.Sockets) == 0 || len(d.System) == 0 || !d.Status.Ready {
		t.Errorf("неполные данные: %d процессов, %d сокетов, %d системных", len(d.Procs), len(d.Sockets), len(d.System))
	}
	if d.Exposure == nil || len(d.Exposure.Entries) == 0 || d.Exposure.Firewall.UFW != "active" {
		t.Errorf("открытые порты: %+v", d.Exposure)
	}
	if d.Fail2ban == nil || !d.Fail2ban.Running || len(d.Fail2ban.Bans) == 0 {
		t.Errorf("fail2ban: %+v", d.Fail2ban)
	}
	// Аудит в этой службе выключен: панель это показывает, запуск — ошибка.
	if d.Audit == nil || d.Audit.Enabled {
		t.Errorf("аудит: %+v", d.Audit)
	}
	if err := rs.RunAudit(); err == nil {
		t.Error("RunAudit при выключенном аудите")
	}
	// Несуществующий процесс — понятная ошибка службы, а не «not found».
	if _, err := rs.Detail("нет-такого"); err == nil || err == errNotFound {
		t.Errorf("Detail несуществующего: %v", err)
	}
	det, err := rs.Detail(d.Procs[0].Key)
	if err != nil || det.Process == nil {
		t.Errorf("Detail: %v", err)
	}
	if err := rs.Rescan(); err != nil {
		t.Errorf("Rescan без CSRF через сокет: %v", err)
	}
	if _, err := DialSocket(filepath.Join(dir, "nope.sock")); err == nil {
		t.Error("подключение к несуществующему сокету должно падать")
	}
}

// cellsAt ищет на экране строку text и возвращает её ячейки.
func cellsAt(a *App, text string) []cell {
	rs := []rune(text)
	for y := 0; y < a.scr.H; y++ {
		row := a.scr.cells[y*a.scr.W : (y+1)*a.scr.W]
		for x := 0; x+len(rs) <= len(row); x++ {
			ok := true
			for i, r := range rs {
				if row[x+i].r != r {
					ok = false
					break
				}
			}
			if ok {
				return row[x : x+len(rs)]
			}
		}
	}
	return nil
}

// TestAddrColor: IP-адреса в панели «Сеть» всегда своего цвета, в том числе
// в выделенной строке, — иначе подсветка Termius «мигает» при прокрутке.
func TestAddrColor(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	press(a, r('4'))
	if len(a.socks) < 2 {
		t.Fatalf("в демо мало сокетов: %d", len(a.socks))
	}
	a.render()
	for i, sk := range a.socks[:2] {
		addr := sk.LocalAddr
		port := fmt.Sprintf(":%d", sk.LocalPort)
		// Ищем вместе с протоколом: тот же адрес есть и в заголовке подробностей.
		pre := fit(sk.Proto, 5) + " "
		cs := cellsAt(a, pre+addr+port)
		if cs == nil {
			t.Fatalf("сокет %d: %s%s не найден в списке", i, addr, port)
		}
		cs = cs[len([]rune(pre)):]
		n := len([]rune(addr))
		for _, c := range cs[:n] {
			if c.st.FG != stAddr.FG {
				t.Errorf("сокет %d: цвет адреса %d, ожидался %d", i, c.st.FG, stAddr.FG)
				break
			}
		}
		selected := i == a.lists[pNet].cursor
		if selected && cs[0].st.BG != stSelFocus.BG {
			t.Errorf("выделенная строка без фона выделения")
		}
		if !selected && cs[n].st.FG != stNormal.FG {
			t.Errorf("сокет %d: цвет порта %d, ожидался цвет по умолчанию", i, cs[n].st.FG)
		}
	}
}

func TestAddrSegs(t *testing.T) {
	segs := addrSegs("10.0.0.1", 22, 21)
	if len(segs) != 2 || segs[0].t != "10.0.0.1" || segs[0].st != stAddr || strWidth(segs[0].t+segs[1].t) != 22 {
		t.Errorf("обычный адрес: %#v", segs)
	}
	long := addrSegs("2001:db8:aaaa:bbbb:cccc::1", 443, 21)
	if len(long) != 1 || strWidth(long[0].t) != 22 || !strings.Contains(long[0].t, "…") {
		t.Errorf("длинный адрес: %#v", long)
	}
}

// TestInvisibleInScreen: символы направления текста и нулевой ширины из
// имени процесса не попадают в терминал.
func TestInvisibleInScreen(t *testing.T) {
	s := newScreen(40, 1)
	s.Text(0, 0, 40, "ss​hd ‮txt.exe", stNormal)
	var out bytes.Buffer
	_ = s.Flush(&out)
	if strings.ContainsAny(out.String(), "​‮") {
		t.Errorf("невидимый символ прошёл в терминал: %q", out.String())
	}
	if got := sanitize("ss​hd"); got != "ss�hd" {
		t.Errorf("sanitize: %q", got)
	}
}

// TestAddrMask: IP-адреса в свободном тексте (события, заголовки) красятся
// без порта, а похожие на них время, версии и MAC — нет.
func TestAddrMask(t *testing.T) {
	cases := []struct{ text, want string }{
		{"соединение с 198.51.100.77:3333.", "198.51.100.77"},
		{"Сокет 0.0.0.0:80", "0.0.0.0"},
		{"порт :::22 и ::1", "::|::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"адрес 10.0.0.1, далее", "10.0.0.1"},
		{"12:32:08 02.01 15:04:05", ""},
		{"go1.24.13 v0.2.2 Ubuntu 24.04", ""},
		{"aa:bb:cc:dd:ee:ff net:[4026531840]", ""},
		{"ver1.2.3.4", ""},
		// Формат события listen из history.listenList.
		{"Начал слушать tcp 127.0.0.1:8090", "127.0.0.1"},
		{"Начал слушать tcp6 :::2222", "::"},
	}
	for _, c := range cases {
		rs := []rune(c.text)
		m := addrMask(rs)
		var got []string
		cur := ""
		for i, r := range rs {
			if m != nil && m[i] {
				cur += string(r)
			} else if cur != "" {
				got = append(got, cur)
				cur = ""
			}
		}
		if cur != "" {
			got = append(got, cur)
		}
		if g := strings.Join(got, "|"); g != c.want {
			t.Errorf("%q: адреса %q, ожидалось %q", c.text, g, c.want)
		}
	}
}

// TestAddrInTitle: адрес в заголовке панели подробностей тоже цвета stAddr.
func TestAddrInTitle(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	press(a, r('4'))
	a.render()
	sk := a.socks[0]
	cs := cellsAt(a, fmt.Sprintf("Сокет %s:%d", sk.LocalAddr, sk.LocalPort))
	if cs == nil {
		t.Fatal("заголовок сокета не найден")
	}
	off := len([]rune("Сокет "))
	if cs[off].st.FG != stAddr.FG || cs[0].st.FG == stAddr.FG {
		t.Errorf("цвета заголовка: «С» %d, адрес %d", cs[0].st.FG, cs[off].st.FG)
	}
}

// TestAddrInHistory: адрес в тексте события в панели «История».
func TestAddrInHistory(t *testing.T) {
	a, _ := newTestApp(t, 160, 45)
	press(a, r('8'))
	a.events[0].Details = i18n.T("hist.listen", "tcp 203.0.113.5:8443")
	a.render()
	cs := cellsAt(a, "203.0.113.5:8443")
	if cs == nil {
		t.Fatal("событие не найдено на экране")
	}
	if cs[0].st.FG != stAddr.FG || cs[len("203.0.113.5")].st.FG == stAddr.FG {
		t.Errorf("цвета: адрес %d, порт %d", cs[0].st.FG, cs[len("203.0.113.5")].st.FG)
	}
}

// hasCyrillic сообщает, есть ли в строке кириллица. Слово «русский» —
// название языка в переключателе — пишется по-русски намеренно.
func hasCyrillic(s string) bool {
	s = strings.ReplaceAll(s, "русский", "")
	return strings.ContainsFunc(s, func(r rune) bool { return r >= 0x400 && r <= 0x4FF })
}

// TestEnglishScreens: на английском ни на одном экране нет русского
// текста (демо-данные — латиница), так ловятся забытые в коде строки.
func TestEnglishScreens(t *testing.T) {
	a, _ := newTestAppLang(t, 160, 60, i18n.EN)
	check := func(what string) {
		t.Helper()
		if s := screen(a); hasCyrillic(s) {
			t.Errorf("%s: русский текст на английском экране:\n%s", what, s)
		}
	}
	check("старт")
	for _, k := range "123456" {
		press(a, r(k))
		check("панель " + string(k))
		press(a, Key{Kind: KeyEnter})
		check("подробности панели " + string(k))
		for range 3 {
			press(a, Key{Kind: KeyDown})
			check("подробности, прокрутка " + string(k))
		}
		press(a, Key{Kind: KeyEsc})
	}
	// Все подозрительные процессы: карточка каждого.
	press(a, r('2'))
	for range len(a.susp) {
		press(a, Key{Kind: KeyEnter})
		a.mainOffset = 0
		for range 20 {
			check("карточка процесса")
			press(a, Key{Kind: KeyPgDn})
		}
		press(a, Key{Kind: KeyEsc}, Key{Kind: KeyDown})
	}
	press(a, r('3'), r('t'))
	check("дерево")
	press(a, r('s'))
	check("сортировка")
	press(a, r('?'))
	check("справка")
	press(a, Key{Kind: KeyEsc}, r('/'))
	check("фильтр")
	press(a, Key{Kind: KeyEsc})
	a.w = 60
	check("узкое окно")
}

func TestLangToggle(t *testing.T) {
	a, _ := newTestAppLang(t, 160, 45, i18n.RU)
	if s := screen(a); !strings.Contains(s, "[2] Подозрительные") {
		t.Fatalf("ожидался русский интерфейс:\n%s", s)
	}
	press(a, r('L'))
	if s := screen(a); !strings.Contains(s, "[2] Suspicious") || !strings.Contains(s, "Language: English") {
		t.Errorf("после L ожидался английский:\n%s", s)
	}
	press(a, r('L'))
	if a.lang != i18n.RU {
		t.Errorf("повторное L должно вернуть русский: %s", a.lang)
	}
}

// TestLayoutHeights: при любой высоте окна панели слева не налезают друг
// на друга и не выходят за экран, а у развёрнутой есть строки списка.
func TestLayoutHeights(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	for _, exp := range []panelID{pSusp, pPorts, pSys} {
		a.focusPanel(exp)
		for h := a.minHeight(); h <= 80; h++ {
			a.w, a.h = 100, h
			a.render()
			y := 0
			for _, p := range a.visible() {
				r := a.rects[p]
				if r.h == 0 && p == pStatus {
					continue
				}
				if r.y != y || r.h < 2 {
					t.Fatalf("h=%d, развёрнута %d: панель %d %+v (ожидалось y=%d)", h, exp, p, r, y)
				}
				y += r.h
			}
			if y != h-1 {
				t.Fatalf("h=%d: панели занимают %d строк из %d", h, y, h-1)
			}
			if ih := a.rects[exp].h - 2; ih < 1 {
				t.Fatalf("h=%d: у развёрнутой панели %d строк", h, ih)
			}
		}
	}
	// 80×24 — привычный размер терминала: в развёрнутой панели видны строки.
	a.w, a.h = 80, 24
	a.focusPanel(pSusp)
	a.render()
	if a.rects[pSusp].h < 6 {
		t.Errorf("80×24: высота развёрнутой панели %d", a.rects[pSusp].h)
	}
}

// TestAuditPanel: панель «Настройки» показывает итоги, r запускает
// проверку заново, y копирует команду исправления.
func TestAuditPanel(t *testing.T) {
	a, out := newTestApp(t, 150, 40)
	press(a, r('6'))
	s := screen(a)
	for _, want := range []string{"[6] Настройки", "Пройдено", "UID 0 только у root", "FAIL", "/etc/passwd:"} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q:\n%s", want, s)
		}
	}
	// Фильтр по тексту фактов.
	press(a, r('/'))
	for _, c := range "cloud-init" {
		press(a, Key{Kind: KeyRune, Rune: c})
	}
	press(a, Key{Kind: KeyEnter})
	if len(a.checks) == 0 {
		t.Fatal("фильтр ничего не нашёл")
	}
	for _, c := range a.checks {
		if !strings.Contains(i18n.Join(" ", c.Evidence...).String()+c.ID, "cloud-init") {
			t.Errorf("лишняя проверка в фильтре: %s", c.ID)
		}
	}
	// Вход по паролю (50-cloud-init.conf) — есть команда исправления.
	idx := -1
	for i, c := range a.checks {
		if c.ID == "ssh_password_auth" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("нет ssh_password_auth")
	}
	a.lists[pAudit].cursor = idx
	out.Reset()
	press(a, r('y'))
	if !strings.Contains(out.String(), "\x1b]52;c;") || a.msgErr {
		t.Errorf("копирование команды: %q %q", out.String(), a.msg)
	}
	// r на панели настроек — повторная проверка, не пересканирование.
	before := a.data.Audit.Time
	time.Sleep(5 * time.Millisecond)
	press(a, r('r'))
	if a.msgErr || !a.data.Audit.Time.After(before) {
		t.Errorf("повторная проверка: %q, время %v → %v", a.msg, before, a.data.Audit.Time)
	}
}

// TestFail2banPanel: панель fail2ban — текущие баны, подробности с
// мини-графиками и командой разбана, y копирует команду.
func TestFail2banPanel(t *testing.T) {
	a, out := newTestApp(t, 160, 50)
	press(a, r('7'))
	if a.focus != pF2B || len(a.bans) == 0 {
		t.Fatalf("фокус %d, банов %d", a.focus, len(a.bans))
	}
	s := screen(a)
	for _, want := range []string{"[7] fail2ban (", "fail2ban запущен", "Попытки по часам", "Включённые jail", "recidive", "Самые активные адреса",
		"fail2ban-client set", "203.0.113.7", "1-9/Tab"} {
		if !strings.Contains(s, want) {
			t.Errorf("на экране нет %q\n%s", want, s)
		}
	}
	out.Reset()
	press(a, r('y'))
	b, _ := a.selBan()
	if want := base64.StdEncoding.EncodeToString([]byte(b.UnbanCommand)); b.UnbanCommand == "" || !strings.Contains(out.String(), want) {
		t.Errorf("y не скопировал команду разбана %q", b.UnbanCommand)
	}
	// Фильтр по IP.
	press(a, r('/'))
	for _, c := range b.IP {
		press(a, r(c))
	}
	press(a, Key{Kind: KeyEnter})
	if len(a.bans) == 0 || a.bans[0].IP != b.IP {
		t.Errorf("фильтр по IP: %+v", a.bans)
	}
	// Сводка упоминает fail2ban.
	press(a, r('1'))
	if s := screen(a); !strings.Contains(s, "забанено") {
		t.Errorf("в обзоре нет fail2ban:\n%s", s)
	}
}

// TestNoFail2banPanel: без fail2ban панели нет, номера сдвигаются,
// клавиша 9 ничего не делает, окно 80×16 по-прежнему помещается.
func TestNoFail2banPanel(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	for k := range tree.HostFiles {
		if strings.Contains(k, "fail2ban") {
			delete(tree.HostFiles, k)
		}
	}
	procs := tree.Procs[:0]
	for _, p := range tree.Procs {
		if p.Comm != "fail2ban-server" {
			procs = append(procs, p)
		}
	}
	tree.Procs = procs
	sc, ar := demoEnvTree(t, tree)
	src, err := NewLocalSource(sc, ar, "test", true, i18n.T("tui.source_demo"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Close)
	a := New(Options{Source: src, Out: &bytes.Buffer{}, Lang: i18n.RU})
	a.w, a.h = 160, 45
	a.load()
	s := screen(a)
	if strings.Contains(s, "fail2ban") || !strings.Contains(s, "[7] История") || !strings.Contains(s, "[8] Система") || !strings.Contains(s, "1-8/Tab") {
		t.Errorf("панели без fail2ban:\n%s", s)
	}
	press(a, r('8'))
	if a.focus != pSys {
		t.Errorf("8 → %d, нужна «Система»", a.focus)
	}
	press(a, r('9'))
	if a.focus != pSys {
		t.Errorf("9 сменила панель: %d", a.focus)
	}
	press(a, Key{Kind: KeyTab})
	if a.focus != pStatus {
		t.Errorf("Tab после последней панели: %d", a.focus)
	}
	if a.minHeight() != 16 {
		t.Errorf("минимальная высота без fail2ban: %d", a.minHeight())
	}
}
