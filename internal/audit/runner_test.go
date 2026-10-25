package audit

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestRunnerLifecycle: Run выполняет аудит сразу, по RunNow — ещё раз,
// и завершается вместе с контекстом, не оставляя горутин.
func TestRunnerLifecycle(t *testing.T) {
	root := accountsTree(t, nil)
	var mu sync.Mutex
	runs := 0
	r := NewRunner(RunnerOptions{HostRoot: root, RootUID: os.Getuid(), Interval: time.Hour, Logger: quiet(),
		Record: func(time.Time, []model.AuditCheck) []model.Event {
			mu.Lock()
			runs++
			mu.Unlock()
			return []model.Event{{Name: "acct_uid0_extra", Risk: model.RiskCritical}}
		}})
	if r.Report() != nil {
		t.Fatal("отчёт до первого запуска")
	}
	g0 := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	waitFor(t, func() bool { return r.Report() != nil })
	first := r.Report()
	if len(first.Checks) == 0 || first.Time.IsZero() {
		t.Fatalf("отчёт: %+v", first)
	}
	// RunNow во время ожидания — внеочередной запуск.
	waitFor(t, func() bool { return !r.Running() })
	if !r.RunNow() {
		t.Fatal("RunNow отклонён без идущей проверки")
	}
	waitFor(t, func() bool { return r.Report() != first })

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился после отмены контекста")
	}
	waitFor(t, func() bool { return runtime.NumGoroutine() <= g0 })
	mu.Lock()
	defer mu.Unlock()
	if runs < 2 {
		t.Errorf("запусков %d", runs)
	}
}

// TestRunNowWhileRunning: пока идёт проверка, новая не запускается и не
// ставится в очередь.
func TestRunNowWhileRunning(t *testing.T) {
	r := NewRunner(RunnerOptions{HostRoot: t.TempDir(), Logger: quiet()})
	r.running.Store(true)
	if r.RunNow() {
		t.Error("RunNow во время проверки")
	}
	r.running.Store(false)
	if !r.RunNow() || r.RunNow() {
		t.Error("второй запрос подряд должен отклоняться: один уже ждёт")
	}
}

// TestRunnerBaselinePersist: базовая линия сохраняется в каталог данных
// с правами 0600 и переживает перезапуск службы.
func TestRunnerBaselinePersist(t *testing.T) {
	root := accountsTree(t, nil)
	dir := t.TempDir()
	r := NewRunner(RunnerOptions{HostRoot: root, RootUID: os.Getuid(), StateDir: dir, Logger: quiet()})
	rep := r.RunOnce()
	for _, c := range rep.Checks {
		if c.ID == "acct_new" && c.Status != model.AuditPass {
			t.Errorf("первая проверка acct_new: %s", c.Status)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, baselineFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("файл базовой линии: %v %v", err, fi)
	}
	data, _ := os.ReadFile(filepath.Join(dir, baselineFile))
	if strings.Contains(string(data), "SECRETHASHVALUE") {
		t.Error("хеш пароля в базовой линии")
	}
	// Новый пользователь после «перезапуска».
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd+"bob:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2 := NewRunner(RunnerOptions{HostRoot: root, RootUID: os.Getuid(), StateDir: dir, Logger: quiet()})
	for _, c := range r2.RunOnce().Checks {
		if c.ID == "acct_new" && (c.Status != model.AuditFail || !strings.Contains(evText(c), "bob")) {
			t.Errorf("новый пользователь с UID 0 после перезапуска: %s %s", c.Status, evText(c))
		}
	}
	// Повреждённый файл не мешает запуску.
	if err := os.WriteFile(filepath.Join(dir, baselineFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r3 := NewRunner(RunnerOptions{HostRoot: root, RootUID: os.Getuid(), StateDir: dir, Logger: quiet()}); r3.RunOnce() == nil {
		t.Error("нет отчёта")
	}
	// Временных файлов не осталось.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("в каталоге данных: %v", entries)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("условие не выполнилось за 5 секунд")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
