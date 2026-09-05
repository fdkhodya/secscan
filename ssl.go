package main

// TLS/SSL-анализ https-целей через testssl.sh (docker-образ
// drwetter/testssl.sh). Проверяются протоколы (-p), параметры сервера (-S)
// и security-заголовки (-h); результат — в JSON (--json-pretty), из которого
// берутся находки с severity ниже OK/INFO.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// sslTargetTimeout — бюджет testssl.sh на одну https-цель.
const sslTargetTimeout = 4 * time.Minute

// maxSSLFindingsPerTarget — чтобы не заваливать отчёт сотнями LOW-записей.
const maxSSLFindingsPerTarget = 30

// sslScan запускает testssl.sh против одной https-цели.
func sslScan(ctx context.Context, cfg *Config, jobID string, idx int, targetURL string) ([]Finding, error) {
	workDir := filepath.Join(cfg.HostDataDir, "work", jobID)
	if err := os.MkdirAll(workDir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(workDir, 0o777)
	outFile := fmt.Sprintf("ssl-%d.json", idx)
	outPath := filepath.Join(workDir, outFile)
	_ = os.Remove(outPath)
	mount := workDir + ":/out"
	args := []string{
		"--jsonfile-pretty=/out/" + outFile,
		"-p", "-S", "-h",
		targetURL,
	}
	_, errOut, err := runDocker(ctx, cfg.SslImage, cfg.DockerNet, []string{mount}, args)
	if err != nil {
		// при недоступной цели testssl может не создать JSON — тогда ошибка;
		// иначе (JSON есть) результат парсим независимо от кода возврата
		if _, statErr := os.Stat(outPath); statErr != nil {
			return nil, fmt.Errorf("testssl: %v: %s", err, tail(errOut, 1500))
		}
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("testssl: JSON не создан: %w", err)
	}
	return parseSSLReport(b, targetURL)
}

// parseSSLReport разбирает JSON testssl.sh. В версиях 4.x результаты лежат
// вложенными объектами {id, severity, finding} внутри scanResult (секции
// protocols/serverDefaults/headerResponse/vulnerabilities и т.п.) — обходим
// дерево рекурсивно и собираем всё с severity ниже OK/INFO.
func parseSSLReport(b []byte, targetURL string) ([]Finding, error) {
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("testssl: parse json: %w", err)
	}
	hostname := ""
	if u, err := url.Parse(targetURL); err == nil {
		hostname = u.Hostname()
	}
	var out []Finding
	seen := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if sevStr, ok := t["severity"].(string); ok {
				if finding, ok2 := t["finding"].(string); ok2 && sslFindingUseful(finding) {
					if sev, ok3 := sslSeverity(sevStr); ok3 {
						sid, _ := t["id"].(string)
						id := "ssl-" + slug(sid)
						if sid == "" {
							id = "ssl-" + shortHash(finding)
						}
						if !seen[id] && len(out) < maxSSLFindingsPerTarget {
							seen[id] = true
							finding = strings.TrimSpace(finding)
							title := finding
							if r := []rune(title); len(r) > 110 {
								title = string(r[:110]) + "…"
							}
							out = append(out, Finding{
								ID:          id,
								Source:      "ssl",
								Severity:    sev,
								Host:        hostname,
								Port:        hostPort(targetURL),
								Protocol:    "tcp",
								URL:         targetURL,
								Title:       title,
								Description: finding,
								Remediation: "Исправьте TLS/SSL-конфигурацию сервера согласно выводу проверки (см. описание и доказательства).",
								Evidence:    "testssl.sh: " + sid,
							})
						}
					}
					return // объект-результат не обходим глубже
				}
			}
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(root)
	return out, nil
}

// sslSeverity переводит severity testssl.sh в модель secscan.
func sslSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical, true
	case "HIGH":
		return SevHigh, true
	case "MEDIUM":
		return SevMedium, true
	case "LOW":
		return SevLow, true
	}
	return SevInfo, false // OK, INFO и прочее — пропускаем
}

// sslFindingUseful отбрасывает пустые/служебные значения finding testssl.sh.
func sslFindingUseful(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	switch s {
	case "--", "-", "not offered", "not tested", "none", "n/a", "no":
		return false
	}
	return true
}

func hostPort(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
