package selfcheck

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type watchdog struct {
	socket   string
	interval time.Duration
}

func watchdogFromEnv() watchdog {
	return parseWatchdog(os.Getenv("NOTIFY_SOCKET"), os.Getenv("WATCHDOG_USEC"), os.Getenv("WATCHDOG_PID"), os.Getpid())
}

func parseWatchdog(socket, usec, pid string, ownPID int) watchdog {
	if pid != "" {
		n, err := strconv.Atoi(pid)
		if err != nil || n != ownPID {
			return watchdog{}
		}
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n < 2 || n > int64((1<<63-1)/time.Microsecond) {
		return watchdog{}
	}
	if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") || len(socket) < 2 {
		return watchdog{}
	}
	return watchdog{socket: socket, interval: time.Duration(n) * time.Microsecond / 2}
}

func (w watchdog) ping() error {
	if w.socket == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: w.socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(min(time.Second, w.interval))); err != nil {
		return err
	}
	_, err = conn.Write([]byte("WATCHDOG=1"))
	return err
}
