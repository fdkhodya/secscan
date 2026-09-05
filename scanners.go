package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ---------- общий запуск docker-контейнеров-сканеров ----------

func runDocker(ctx context.Context, image, network string, mounts []string, cmdArgs []string) (stdout, stderr string, err error) {
	args := []string{"run", "--rm"}
	if network == "host" {
		// Linux: сеть хоста (сканирование localhost и LAN как с самого хоста).
		// Docker Desktop (Windows/macOS): --network host недоступен —
		// задайте SECSCAN_DOCKER_NETWORK= (пусто) для bridge-сети.
		args = append(args, "--network", "host")
	}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	args = append(args, image)
	args = append(args, cmdArgs...)
	return execCmd(ctx, "docker", args...)
}

func execCmd(ctx context.Context, name string, args ...string) (stdout, stderr string, err error) {
	cmd := execCommandContext(ctx, name, args...)
	var ob, eb bytes.Buffer
	cmd.Stdout = &ob
	cmd.Stderr = &eb
	err = cmd.Run()
	return ob.String(), eb.String(), err
}

// ---------- nmap ----------

type nmapHost struct {
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports  []nmapPort `xml:"ports>port"`
	Script []nmapScr  `xml:"hostscript>script"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
	Script []nmapScr `xml:"script"`
}

type nmapScr struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapResult struct {
	Hosts []nmapHost `xml:"host"`
}

// nmapScan возвращает находки и список открытых веб-портов.
// vulners — NSE-скрипт vulners (CVE по версиям); nse — доп. безопасные
// NSE-скрипты (ssl-enum-ciphers, http-security-headers).
func nmapScan(ctx context.Context, cfg *Config, host string, vulners, nse bool) ([]Finding, []int, error) {
	args := []string{
		"-Pn", "-sV", "-T4", "--top-ports", "1000", "--open",
		"--host-timeout", "15m", "-oX", "-",
	}
	var scripts []string
	if vulners {
		// NSE vulners — сверка CVE по vulners.com (нужен исходящий HTTPS)
		scripts = append(scripts, "vulners")
	}
	if nse {
		// доп. безопасные NSE-скрипты: TLS-протоколы/шифры, HTTP-методы/TRACE
		scripts = append(scripts, "ssl-enum-ciphers", "http-methods", "http-trace")
	}
	if len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}
	args = append(args, host)
	out, errOut, err := runDocker(ctx, cfg.NmapImage, cfg.DockerNet, nil, args)
	if err != nil {
		// nmap может вернуть ненулевой код при частичном скане (rc>0),
		// XML при этом часто валиден — пробуем распарсить.
		if !strings.Contains(out, "<nmaprun") {
			return nil, nil, fmt.Errorf("nmap: %v: %s", err, tail(errOut, 1500))
		}
	}
	findings, webPorts, err := parseNmapResults(out)
	if err != nil {
		return nil, nil, err
	}
	return findings, webPorts, nil
}

// nmapUDPScan — сканирование топ-50 UDP-портов (по тумблеру).
func nmapUDPScan(ctx context.Context, image, network, host string) ([]Finding, error) {
	args := []string{
		"-Pn", "-sU", "-T4", "--top-ports", "50", "--open",
		"--host-timeout", "10m", "-oX", "-", host,
	}
	out, errOut, err := runDocker(ctx, image, network, nil, args)
	if err != nil {
		if !strings.Contains(out, "<nmaprun") {
			return nil, fmt.Errorf("nmap-udp: %v: %s", err, tail(errOut, 1500))
		}
	}
	findings, _, err := parseNmapResults(out)
	if err != nil {
		return nil, fmt.Errorf("nmap-udp xml parse: %w", err)
	}
	return findings, nil
}

// parseNmapResults разбирает XML nmap (-oX -) в находки и веб-порты.
func parseNmapResults(out string) ([]Finding, []int, error) {
	var res nmapResult
	if err := xml.Unmarshal([]byte(out), &res); err != nil {
		return nil, nil, fmt.Errorf("nmap xml parse: %w", err)
	}
	var findings []Finding
	webPorts := map[int]bool{}
	for _, h := range res.Hosts {
		addr := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				addr = a.Addr
			}
		}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			if isWebPort(p.PortID) {
				webPorts[p.PortID] = true
			}
			f := portFinding(addr, p)
			findings = append(findings, f)
			// NSE-скрипты порта (vulners, ssl-enum-ciphers, http-security-headers...)
			for _, s := range p.Script {
				findings = append(findings, scriptFindings(addr, p, s)...)
			}
		}
		for _, s := range h.Script {
			findings = append(findings, scriptFindings(addr, nmapPort{}, s)...)
		}
	}
	var ports []int
	for p := range webPorts {
		ports = append(ports, p)
	}
	return findings, ports, nil
}

func isWebPort(p int) bool {
	switch p {
	case 80, 443, 8080, 8443, 8000, 8888, 3000, 9000, 9443:
		return true
	}
	return false
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func portFinding(host string, p nmapPort) Finding {
	f := Finding{
		ID:       fmt.Sprintf("nmap-port-%d-%s", p.PortID, p.Protocol),
		Source:   "nmap",
		Severity: SevInfo,
		Host:     host,
		Port:     p.PortID,
		Protocol: p.Protocol,
		Title:    fmt.Sprintf("Открытый порт %d/%s: %s", p.PortID, p.Protocol, p.Service.Name),
	}
	svc := p.Service
	detail := strings.TrimSpace(strings.Join([]string{svc.Product, svc.Version}, " "))
	f.Evidence = fmt.Sprintf("Сервис: %s %s", svc.Name, detail)
	f.Description = fmt.Sprintf("Порт %d/%s открыт. Обнаружен сервис: %s (%s).",
		p.PortID, p.Protocol, svc.Name, detail)
	f.Remediation = remediationForService(svc.Name, p.PortID)
	if sev, title, ok := weakService(svc.Name, p.PortID); ok {
		f.Severity = sev
		f.Title = title
	}
	return f
}

// scriptFindings разбирает NSE-скрипты: vulners (CVE+CVSS), "VULNERABLE",
// ssl-enum-ciphers, http-methods, http-trace.
func scriptFindings(host string, p nmapPort, s nmapScr) []Finding {
	switch s.ID {
	case "ssl-enum-ciphers":
		return sslCipherFindings(host, p, s)
	case "http-methods":
		return httpMethodsFindings(host, p, s)
	case "http-trace":
		return httpTraceFindings(host, p, s)
	}
	var out []Finding
	low := strings.ToLower(s.Output)
	if strings.Contains(low, "vulnerable") || strings.HasPrefix(s.ID, "http-vuln") ||
		strings.HasPrefix(s.ID, "ssl-") && strings.Contains(low, "vulnerable") {
		out = append(out, Finding{
			ID:          fmt.Sprintf("nmap-nse-%s-%s", s.ID, host),
			Source:      "nmap",
			Severity:    SevMedium,
			Host:        host,
			Port:        p.PortID,
			Protocol:    p.Protocol,
			Title:       fmt.Sprintf("NSE: %s — потенциальная уязвимость", s.ID),
			Description: "Скрипт NSE " + s.ID + " сообщает о возможной уязвимости: " + firstLine(s.Output),
			Evidence:    s.Output,
			Remediation: "Изучите вывод скрипта, обновите продукт/версию, примените рекомендации производителя.",
		})
		return out
	}
	if s.ID == "vulners" {
		for _, m := range vulnersRe.FindAllStringSubmatch(s.Output, -1) {
			if len(m) < 3 {
				continue
			}
			cve := strings.ToUpper(m[1])
			cvss, _ := strconv.ParseFloat(m[2], 64)
			sev := sevFromCVSS(cvss)
			rem := fmt.Sprintf("Обновите %s до актуальной версии с исправлением %s.",
				p.Service.Name, cve)
			if sev.rank() < SevHigh.rank() {
				rem = "Проверьте актуальность версии и наличие патча (" + cve + ")."
			}
			out = append(out, Finding{
				ID:       "nmap-vulners-" + cve,
				Source:   "nmap",
				Severity: sev,
				CVSS:     cvss,
				CVE:      cve,
				Host:     host,
				Port:     p.PortID,
				Protocol: p.Protocol,
				Title:    fmt.Sprintf("%s на %s %s", cve, p.Service.Name, p.Service.Version),
				Description: fmt.Sprintf("База vulners (NSE) сообщает об уязвимости %s (CVSS %.1f) в %s %s.",
					cve, cvss, p.Service.Name, p.Service.Version),
				Remediation: rem,
				Evidence:    firstLine(s.Output),
			})
		}
	}
	return out
}

var vulnersRe = regexp.MustCompile(`(CVE-\d{4}-\d{4,7})[^\n]*?(\d+\.\d+)`)

// sslCipherFindings — разбор NSE ssl-enum-ciphers: устаревшие протоколы,
// слабые шифры (least strength), TLS-сжатие (CRIME).
func sslCipherFindings(host string, p nmapPort, s nmapScr) []Finding {
	var out []Finding
	weakProto := map[string]Severity{
		"SSLv2": SevCritical, "SSLv3": SevHigh,
		"TLSv1.0": SevMedium, "TLSv1.1": SevMedium,
	}
	for proto, sev := range weakProto {
		re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(proto) + `:[ \t]*$`)
		if !re.MatchString(s.Output) {
			continue
		}
		rem := "Отключите " + proto + " в конфигурации TLS; оставьте только TLS 1.2 и TLS 1.3."
		if sev == SevCritical {
			rem = "Немедленно отключите " + proto + " — протокол полностью скомпрометирован."
		}
		out = append(out, Finding{
			ID:          "nmap-ssl-proto-" + strings.ToLower(strings.ReplaceAll(proto, ".", "-")) + "-" + host,
			Source:      "nmap",
			Severity:    sev,
			Host:        host,
			Port:        p.PortID,
			Protocol:    "tcp",
			Title:       "Включён устаревший протокол " + proto,
			Description: "Сервер на порту " + strconv.Itoa(p.PortID) + " поддерживает устаревший протокол " + proto + " — он небезопасен и должен быть отключён.",
			Remediation: rem,
			Evidence:    firstLine(s.Output),
		})
	}
	if m := nmapLeastStrengthRe.FindStringSubmatch(s.Output); m != nil {
		st := m[1]
		sev := SevInfo
		label := ""
		switch st {
		case "F", "E", "D":
			sev, label = SevHigh, "очень слабые шифры"
		case "C":
			sev, label = SevMedium, "слабые шифры"
		case "B":
			sev, label = SevLow, "относительно слабые шифры"
		case "A":
			label = "сильные шифры"
		}
		if sev != SevInfo {
			out = append(out, Finding{
				ID:          "nmap-ssl-strength-" + st + "-" + host,
				Source:      "nmap",
				Severity:    sev,
				Host:        host,
				Port:        p.PortID,
				Protocol:    "tcp",
				Title:       "Слабые TLS-шифры (уровень " + st + ")",
				Description: "NSE ssl-enum-ciphers оценивает минимальную стойкость шифров сервера как " + st + " (" + label + ").",
				Remediation: "Настройте TLS: отключите слабые шифры (RC4, 3DES, экспортные, CBC без AEAD), оставьте только современные наборы.",
				Evidence:    firstLine(s.Output),
			})
		}
	}
	if strings.Contains(s.Output, "compressors:") && strings.Contains(s.Output, "DEFLATE") {
		out = append(out, Finding{
			ID:          "nmap-ssl-crime-" + host,
			Source:      "nmap",
			Severity:    SevHigh,
			Host:        host,
			Port:        p.PortID,
			Protocol:    "tcp",
			Title:       "Включено TLS-сжатие (уязвимость CRIME)",
			Description: "Сервер поддерживает сжатие TLS (DEFLATE) — возможна атака CRIME на секреты в TLS.",
			Remediation: "Отключите сжатие TLS на сервере.",
			Evidence:    firstLine(s.Output),
		})
	}
	return out
}

var nmapLeastStrengthRe = regexp.MustCompile(`(?m)least strength:[ \t]*([A-F])`)

// httpMethodsFindings — разбор NSE http-methods: разрешённые опасные методы.
func httpMethodsFindings(host string, p nmapPort, s nmapScr) []Finding {
	m := nmapRiskyMethodsRe.FindStringSubmatch(s.Output)
	if m == nil || strings.TrimSpace(m[1]) == "" {
		return nil
	}
	methods := strings.TrimSpace(m[1])
	return []Finding{{
		ID:          "nmap-http-methods-" + host,
		Source:      "nmap",
		Severity:    SevMedium,
		Host:        host,
		Port:        p.PortID,
		Protocol:    p.Protocol,
		Title:       "Разрешены опасные HTTP-методы",
		Description: "Веб-сервер разрешает опасные HTTP-методы: " + methods + ". Они могут использоваться для изменения/удаления ресурсов (PUT/DELETE), обхода ограничений (TRACE, CONNECT) и т.п.",
		Remediation: "Отключите неиспользуемые HTTP-методы (PUT, DELETE, TRACE, CONNECT и др.) на уровне веб-сервера/приложения.",
		Evidence:    firstLine(s.Output),
	}}
}

var nmapRiskyMethodsRe = regexp.MustCompile(`(?i)potentially risky methods:[ \t]*([A-Z][A-Z ,]*)`)

// httpTraceFindings — разбор NSE http-trace: включённый TRACE (XST).
func httpTraceFindings(host string, p nmapPort, s nmapScr) []Finding {
	if !strings.Contains(s.Output, "TRACE is enabled") {
		return nil
	}
	return []Finding{{
		ID:          "nmap-http-trace-" + host,
		Source:      "nmap",
		Severity:    SevMedium,
		Host:        host,
		Port:        p.PortID,
		Protocol:    p.Protocol,
		Title:       "Включён HTTP TRACE (риск XST)",
		Description: "Веб-сервер разрешает метод TRACE — возможна атака Cross-Site Tracing (XST), в частности кража HttpOnly-куки при XSS.",
		Remediation: "Отключите метод TRACE на веб-сервере.",
		Evidence:    firstLine(s.Output),
	}}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// ---------- OWASP ZAP (baseline) ----------

// flexibleInt принимает число или строку из JSON ZAP.
type flexibleInt struct{ Val int }

func (f *flexibleInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil // не критично для отчёта
	}
	f.Val = n
	return nil
}

type zapReport struct {
	Site []struct {
		Name   string     `json:"name"`
		Alerts []zapAlert `json:"alerts"`
	} `json:"site"`
}

type zapAlert struct {
	Alert      string        `json:"alert"`
	RiskCode   flexibleInt   `json:"riskcode"`
	Confidence string        `json:"confidence"`
	Desc       string        `json:"desc"`
	Solution   string        `json:"solution"`
	Instances  []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Evidence string `json:"evidence"`
}

// zapScan запускает zap-baseline против одного URL.
func zapScan(ctx context.Context, image, network, hostDataDir, jobID, targetURL string) ([]Finding, error) {
	workDir := filepath.Join(hostDataDir, "work", jobID)
	if err := os.MkdirAll(workDir, 0o777); err != nil {
		return nil, err
	}
	// Каталог создаёт root (secscan/docker), а zap-контейнер пишет от своего
	// пользователя (uid 1000 zap) — открываем на запись всем, иначе
	// zap-baseline падает: Permission denied: '/zap/wrk/zap.yaml'.
	if err := os.Chmod(workDir, 0o777); err != nil {
		return nil, err
	}
	reportJSON := filepath.Join(workDir, "zap.json")
	_ = os.Remove(reportJSON)
	mount := workDir + ":/zap/wrk"
	args := []string{
		"zap-baseline.py", "-t", targetURL,
		// Имя файла ОТНОСИТЕЛЬНОЕ: абсолютный путь (-J /zap/wrk/zap.json)
		// ломает генерацию отчёта — automation-фреймворк склеивает reportDir
		// с reportFile и пишет в /zap/wrk/zap/wrk/zap.json (NoSuchFileException).
		// zap-baseline кладёт zap.json в /zap/wrk (смонтированный workDir).
		"-J", "zap.json",
	}
	_, errOut, err := runDocker(ctx, image, network, []string{mount}, args)
	if err != nil {
		// zap-baseline: rc=0 — PASS, rc=1 — найдены FAIL, rc=2 — найдены WARN:
		// штатные завершения, отчёт zap.json при этом создаётся. Ошибка —
		// только если отчёта нет (rc=3+: ZAP не стартовал и т.п.).
		if _, statErr := os.Stat(reportJSON); statErr != nil {
			return nil, fmt.Errorf("zap: %v: %s", err, tail(errOut, 2000))
		}
	}
	b, err := os.ReadFile(reportJSON)
	if err != nil {
		return nil, fmt.Errorf("zap: отчёт не создан: %w", err)
	}
	var rep zapReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("zap: parse report: %w", err)
	}
	var findings []Finding
	for _, site := range rep.Site {
		for _, a := range site.Alerts {
			sev := SevInfo
			switch a.RiskCode.Val {
			case 3:
				sev = SevHigh
			case 2:
				sev = SevMedium
			case 1:
				sev = SevLow
			}
			title, desc, rem := a.Alert, stripTags(a.Desc), stripTags(a.Solution)
			if tr, ok := zapI18nFor(a.Alert); ok {
				// правило переведено — выдаём русский текст целиком
				title, desc, rem = tr.Title, tr.Desc, tr.Sol
			}
			f := Finding{
				ID:          "zap-" + slug(a.Alert),
				Source:      "zap",
				Severity:    sev,
				Host:        site.Name,
				URL:         site.Name,
				Title:       title,
				Description: desc,
				Remediation: rem,
				Confidence:  a.Confidence,
			}
			if len(a.Instances) > 0 {
				f.Evidence = fmt.Sprintf("%s %s %s",
					a.Instances[0].Method, a.Instances[0].URI, a.Instances[0].Evidence)
				f.URL = a.Instances[0].URI
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string {
	s = htmlTagRe.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	return strings.TrimSpace(s)
}

func slug(s string) string {
	re := regexp.MustCompile(`[^a-z0-9]+`)
	return strings.Trim(re.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// resolveHost извлекает хост для nmap из ввода пользователя.
func resolveHost(target string) string {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return target
}

// isURLTarget — ввод пользователя является http(s) URL.
func isURLTarget(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}
