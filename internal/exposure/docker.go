package exposure

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

const (
	// maxContainers — сколько каталогов контейнеров читать за сканирование.
	maxContainers = 4096
	// maxContainerConfig — предел размера config.v2.json. В нём есть
	// переменные окружения и метки, но даже у больших контейнеров файл —
	// десятки килобайт.
	maxContainerConfig = 2 << 20
	// defaultDockerRoot — каталог данных Docker по умолчанию.
	defaultDockerRoot = "/var/lib/docker"
)

// containerConfig — нужные поля config.v2.json. Из Env остаются только
// имена переменных; значения и метки не сохраняются и не выводятся.
type containerConfig struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Config struct {
		Image string   `json:"Image"`
		User  string   `json:"User"`
		Env   envNames `json:"Env"`
	} `json:"Config"`
	MountPoints map[string]mountConfig `json:"MountPoints"`
	State       struct {
		Running bool `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// dockerRoot — каталог данных Docker из /etc/docker/daemon.json
// (data-root, в старых версиях graph) или путь по умолчанию.
func dockerRoot(hostRoot string) string {
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		return filepath.Join(hostRoot, defaultDockerRoot)
	}
	defer root.Close()
	p, _ := dockerRootPath(root)
	return filepath.Join(hostRoot, p)
}

func dockerRootPath(root *os.Root) (string, error) {
	data, _, err := safefile.ReadRooted(root, "etc/docker/daemon.json", maxConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return defaultDockerRoot, nil
	}
	if err != nil {
		return defaultDockerRoot, err
	}
	var cfg struct {
		DataRoot string `json:"data-root"`
		Graph    string `json:"graph"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultDockerRoot, err
	}
	for _, r := range []string{cfg.DataRoot, cfg.Graph} {
		if r == "" {
			continue
		}
		if !filepath.IsAbs(r) {
			return defaultDockerRoot, os.ErrInvalid
		}
		return filepath.Clean(r), nil
	}
	return defaultDockerRoot, nil
}

// ReadDocker возвращает опубликованные порты работающих контейнеров из
// <data-root>/containers/*/config.v2.json. Там записаны фактические
// привязки (NetworkSettings.Ports), в том числе при userland-proxy=false,
// когда процессов docker-proxy нет. Docker API не используется: сокет
// Docker даёт root, и службе наблюдения он не нужен.
func ReadDocker(hostRoot string) ([]model.PortBinding, []i18n.Msg) {
	data := readDockerData(hostRoot, false)
	return data.bindings, data.warnings
}

// ParseContainerConfig извлекает опубликованные порты из config.v2.json.
// Остановленный контейнер портов не держит — для него пусто.
func ParseContainerConfig(data []byte) []model.PortBinding {
	var c containerConfig
	if err := json.Unmarshal(data, &c); err != nil || !c.State.Running {
		return nil
	}
	name := strings.TrimPrefix(c.Name, "/")
	var out []model.PortBinding
	for spec, binds := range c.NetworkSettings.Ports {
		port, proto, ok := strings.Cut(spec, "/")
		cport, err := strconv.Atoi(port)
		if !ok || err != nil || cport <= 0 || cport > 65535 || (proto != "tcp" && proto != "udp") {
			continue
		}
		for _, b := range binds {
			hport, err := strconv.Atoi(b.HostPort)
			if err != nil || hport <= 0 || hport > 65535 {
				continue
			}
			ip := b.HostIP
			if ip == "" {
				ip = "0.0.0.0"
			}
			out = append(out, model.PortBinding{ContainerID: shortID(c.ID), ContainerName: name, Image: c.Config.Image,
				Proto: proto, HostIP: ip, HostPort: hport, ContainerPort: cport, Source: "config"})
		}
	}
	return out
}

// ParseDockerProxyArgs разбирает командную строку docker-proxy:
// -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2
// -container-port 80. Флаги в стиле пакета flag: -x v, --x v, -x=v.
func ParseDockerProxyArgs(args []string) (model.PortBinding, bool) {
	vals := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		k := strings.TrimLeft(a, "-")
		if key, v, ok := strings.Cut(k, "="); ok {
			vals[key] = v
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			vals[k] = args[i+1]
			i++
		}
	}
	hport, err1 := strconv.Atoi(vals["host-port"])
	cport, err2 := strconv.Atoi(vals["container-port"])
	proto := vals["proto"]
	if proto == "" {
		proto = "tcp"
	}
	if err1 != nil || err2 != nil || hport <= 0 || hport > 65535 || cport <= 0 || cport > 65535 || (proto != "tcp" && proto != "udp") {
		return model.PortBinding{}, false
	}
	ip := vals["host-ip"]
	if ip == "" {
		ip = "0.0.0.0"
	}
	return model.PortBinding{Proto: proto, HostIP: ip, HostPort: hport, ContainerPort: cport, Source: "docker-proxy"}, true
}

// isContainerID — имя каталога контейнера: 64 шестнадцатеричных символа.
func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
