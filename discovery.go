package main

// Поиск сайтов, обслуживаемых тем же IP: secscan умеет за один запуск
// находить и проверять все http/https-сервисы на цели.
//
// Источники имён:
//  1. TLS-сертификаты (SAN) по открытым https-портам;
//  2. реестр Certificate Transparency (crt.sh) по «базовому» домену
//     (отключается env SECSCAN_CRTSH=0) — публичный реестр сертификатов.
//
// Каждый кандидат обязан резолвиться в IP цели (A-запись), поэтому
// посторонние имена отсекаются. Запросы к crt.sh — единственный внешний
// вызов discovery.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// maxDiscoveredNames — сколько дополнительных сайтов берём в обработку.
	maxDiscoveredNames = 15
	// maxZapTargets — максимум URL на один запуск ZAP (лимит времени скана).
	maxZapTargets = 12
	// zapTargetTimeout — бюджет на один сайт в ZAP-этапе.
	zapTargetTimeout = 20 * time.Minute
	// crtshTimeout — crt.sh бывает медленным; при ошибке discovery просто
	// продолжает с тем, что нашёл по TLS-сертификатам.
	crtshTimeout = 20 * time.Second
	// tlsProbeTimeout — на один порт при чтении сертификата.
	tlsProbeTimeout = 4 * time.Second
)

// discoverSiteNames возвращает домены, обслуживаемые тем же IP, что и цель
// job'а (host). Пустой результат — веб-имён не нашлось (или они не
// резолвятся в этот IP).
func discoverSiteNames(ctx context.Context, cfg *Config, job *Job, webPorts []int) []string {
	host := strings.Trim(job.Host, "[]")
	names := map[string]bool{}
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimPrefix(n, "*.")
		if n == "" || strings.ContainsAny(n, "* ") || net.ParseIP(n) != nil {
			return
		}
		names[n] = true
	}

	// 1) имена из TLS-сертификатов по открытым веб-портам
	for _, p := range webPorts {
		for _, n := range tlsSANNames(host, p) {
			add(n)
		}
	}

	// 2) crt.sh по базовому домену (введённый домен или домен из SAN)
	if cfg.Crtsh {
		base := ""
		if ip := net.ParseIP(host); ip == nil {
			base = baseDomain(host) // цель задана доменом
		} else if len(names) > 0 {
			base = baseDomain(sortedKeys(names)[0])
		}
		if base != "" && base != host {
			for _, n := range crtshNames(ctx, base) {
				add(n)
			}
		}
	}

	// 3) оставляем только тех, кто резолвится в IP цели (и не саму цель)
	hostIPs := []string{host}
	if ip := net.ParseIP(host); ip == nil {
		if addrs, err := net.LookupHost(host); err == nil {
			hostIPs = addrs
		}
	}
	var out []string
	for _, n := range sortedKeys(names) {
		if n == host {
			continue
		}
		if addrs, err := net.LookupHost(n); err == nil && ipIntersect(hostIPs, addrs) {
			out = append(out, n)
		}
		if len(out) >= maxDiscoveredNames {
			break
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ipIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// tlsSANNames читает имена DNS из сертификата хоста на порту (если это TLS).
func tlsSANNames(host string, port int) []string {
	if port <= 0 {
		return nil
	}
	d := &net.Dialer{Timeout: tlsProbeTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true}) // сертификат читаем, не проверяем
	if err != nil {
		return nil
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0].DNSNames
}

// baseDomain — две последние метки домена: music.fdkh.ru -> fdkh.ru.
// Для IP и коротких имён возвращает имя как есть (вызывающий проверяет).
func baseDomain(name string) string {
	parts := strings.Split(strings.Trim(name, "."), ".")
	if len(parts) <= 2 {
		return name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// crtshNames запрашивает сертификаты домена (и поддоменов) у crt.sh.
func crtshNames(ctx context.Context, domain string) []string {
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "secscan/1.0")
	client := &http.Client{Timeout: crtshTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&entries); err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, e := range entries {
		values := strings.Split(e.NameValue, "\n")
		if e.CommonName != "" {
			values = append(values, e.CommonName)
		}
		for _, v := range values {
			v = strings.ToLower(strings.TrimSpace(v))
			v = strings.TrimPrefix(v, "*.")
			if v == "" || strings.ContainsAny(v, "* ") {
				continue
			}
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

// webTargetList собирает полный список URL для веб-сканеров (ZAP, nuclei):
// цель job'а (IP/домен) + найденные сайты на том же IP (по открытым портам
// 80/443).
func webTargetList(ctx context.Context, cfg *Config, job *Job, webPorts []int) []string {
	urls := zapTargets(job, webPorts)
	// расширяем соседями только когда цель задана без схемы (IP или домен):
	// явный URL пользователь указал сам — сканируем только его
	if job.URL == "" {
		for _, name := range discoverSiteNames(ctx, cfg, job, webPorts) {
			if portOpen(webPorts, 443) {
				urls = append(urls, "https://"+name)
			}
			if portOpen(webPorts, 80) {
				urls = append(urls, "http://"+name)
			}
		}
	}
	return mergeURLs(urls)
}

// zapTargets — базовые URL цели по открытым веб-портам (или явный URL).
func zapTargets(j *Job, webPorts []int) []string {
	if j.URL != "" {
		return []string{j.URL}
	}
	var out []string
	for _, p := range webPorts {
		scheme := "http"
		if p == 443 || p == 8443 || p == 9443 {
			scheme = "https"
		}
		out = append(out, fmt.Sprintf("%s://%s", scheme, joinHostPort(j.Host, p)))
	}
	return out
}

// sslTargetList — https-цели для TLS/SSL-анализа (testssl.sh).
func sslTargetList(ctx context.Context, cfg *Config, job *Job, webPorts []int) []string {
	var out []string
	if job.URL != "" {
		if strings.HasPrefix(job.URL, "https://") {
			out = append(out, job.URL)
		}
		return mergeURLs(out)
	}
	httpsPorts := map[int]bool{}
	for _, p := range webPorts {
		if p == 443 || p == 8443 || p == 9443 {
			httpsPorts[p] = true
		}
	}
	if len(httpsPorts) == 0 {
		return nil
	}
	// сортировка портов для детерминизма
	var ports []int
	for p := range httpsPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		out = append(out, fmt.Sprintf("https://%s", joinHostPort(job.Host, p)))
	}
	for _, name := range discoverSiteNames(ctx, cfg, job, webPorts) {
		if httpsPorts[443] {
			out = append(out, "https://"+name)
		}
	}
	return mergeURLs(out)
}

func portOpen(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// mergeURLs убирает дубли и ограничивает число целей (maxZapTargets).
func mergeURLs(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if len(out) >= maxZapTargets {
			break
		}
	}
	return out
}
