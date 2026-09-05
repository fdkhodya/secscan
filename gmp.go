package main

// GMP-клиент к gvmd (Greenbone Community Edition).
//
// Greenbone-стек запускается в ТОМ ЖЕ docker-compose, что и secscan
// (профиль greenbone, см. docker-compose.yml). secscan общается с gvmd
// напрямую по протоколу GMP через общий unix-сокет /run/gvmd/gvmd.sock
// (volume gvmd_socket_vol монтируется и в gvmd, и в secscan) — ровно так,
// как это делают штатные gsad/gvm-tools. Никаких TCP-портов, TLS-сертификатов
// и внешних «мостов» не требуется.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// gmpPollInterval — как часто опрашиваем статус задачи OpenVAS.
var gmpPollInterval = 20 * time.Second

// gmpCommandTimeout — лимит на один запрос/ответ (опрос идёт чаще).
const gmpCommandTimeout = 3 * time.Minute

// socketExists — есть ли unix-сокет (используется и engine.go).
func socketExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// gmpRaw — «сырой» ответ GMP: атрибуты корня + внутренний XML.
type gmpRaw struct {
	XMLName    xml.Name
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
	ID         string `xml:"id,attr"`
	Inner      []byte `xml:",innerxml"`
}

// ok проверяет статус ответа GMP (2xx — успех).
func (r gmpRaw) ok() error {
	if r.Status == "" {
		return fmt.Errorf("пустой ответ GMP (%s)", r.XMLName.Local)
	}
	code, err := strconv.Atoi(r.Status)
	if err != nil || code < 200 || code >= 300 {
		return fmt.Errorf("GMP %s: %s", r.Status, strings.TrimSpace(r.StatusText))
	}
	return nil
}

// gmpClient — соединение с gvmd по unix-сокету.
type gmpClient struct {
	conn net.Conn
	rd   *bufio.Reader
}

func dialGMP(ctx context.Context, socket string) (*gmpClient, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	return &gmpClient{conn: conn, rd: bufio.NewReader(conn)}, nil
}

func (c *gmpClient) close() { _ = c.conn.Close() }

// cmd отправляет один GMP-запрос и читает один ответ.
func (c *gmpClient) cmd(ctx context.Context, payload string) (gmpRaw, error) {
	var resp gmpRaw
	// лимит на команду: не дольше gmpCommandTimeout, но и не позже ctx
	dl := time.Now().Add(gmpCommandTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = c.conn.SetDeadline(dl)

	req := "<GMP version=\"20.08\">" + payload + "</GMP>\n"
	if _, err := io.WriteString(c.conn, req); err != nil {
		return resp, fmt.Errorf("запрос GMP: %w", err)
	}
	if err := xml.NewDecoder(c.rd).Decode(&resp); err != nil {
		return resp, fmt.Errorf("ответ GMP: %w", err)
	}
	if !strings.HasSuffix(resp.XMLName.Local, "_response") {
		return resp, fmt.Errorf("неожиданный ответ GMP: %s", resp.XMLName.Local)
	}
	return resp, nil
}

// esc экранирует значение для XML.
func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// parseInner разбирает Inner (несколько элементов без общего корня),
// оборачивая его синтетическим корнем.
func parseInner(inner []byte, v any) error {
	doc := make([]byte, 0, len(inner)+13)
	doc = append(doc, "<root>"...)
	doc = append(doc, inner...)
	doc = append(doc, "</root>"...)
	return xml.Unmarshal(doc, v)
}

func (c *gmpClient) authenticate(ctx context.Context, user, pass string) error {
	p := fmt.Sprintf("<authenticate><credentials><username>%s</username><password>%s</password></credentials></authenticate>",
		esc(user), esc(pass))
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return fmt.Errorf("gvmd: %w", err)
	}
	if err := raw.ok(); err != nil {
		return fmt.Errorf("gvmd: авторизация: %w", err)
	}
	return nil
}

// pickConfigID находит конфиг сканирования «Full and fast» (или первый).
func (c *gmpClient) pickConfig(ctx context.Context) (id, name string, err error) {
	raw, err := c.cmd(ctx, "<get_configs/>")
	if err != nil {
		return "", "", fmt.Errorf("get_configs: %w", err)
	}
	if err := raw.ok(); err != nil {
		return "", "", err
	}
	var list struct {
		Configs []struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"config"`
	}
	if err := parseInner(raw.Inner, &list); err != nil {
		return "", "", fmt.Errorf("get_configs: parse: %w", err)
	}
	var fallbackID, fallbackName string
	for _, cf := range list.Configs {
		if cf.ID == "" {
			continue
		}
		if fallbackID == "" {
			fallbackID, fallbackName = cf.ID, cf.Name
		}
		if strings.EqualFold(strings.TrimSpace(cf.Name), "Full and fast") {
			return cf.ID, cf.Name, nil
		}
		if strings.Contains(strings.ToLower(cf.Name), "full and fast") {
			return cf.ID, cf.Name, nil
		}
	}
	if fallbackID != "" {
		return fallbackID, fallbackName, nil
	}
	return "", "", fmt.Errorf("в gvmd нет ни одного конфига сканирования")
}

// pickPortListID ищет порт-лист «All IANA assigned TCP» (или первый).
func (c *gmpClient) pickPortListID(ctx context.Context) string {
	raw, err := c.cmd(ctx, "<get_port_lists/>")
	if err != nil || raw.ok() != nil {
		return ""
	}
	var list struct {
		Lists []struct {
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"port_list"`
	}
	if err := parseInner(raw.Inner, &list); err != nil {
		return ""
	}
	var first string
	for _, pl := range list.Lists {
		if pl.ID == "" {
			continue
		}
		if first == "" {
			first = pl.ID
		}
		n := strings.ToLower(pl.Name)
		if strings.Contains(n, "all iana") && strings.Contains(n, "tcp") && !strings.Contains(n, "udp") {
			return pl.ID
		}
	}
	return first
}

func (c *gmpClient) createTarget(ctx context.Context, name, host string) (string, error) {
	p := fmt.Sprintf("<create_target><name>%s</name><hosts>%s</hosts><comment>secscan</comment></create_target>",
		esc(name), esc(host))
	// порт-лист по умолчанию — best effort
	if pl := c.pickPortListID(ctx); pl != "" {
		p = fmt.Sprintf("<create_target><name>%s</name><hosts>%s</hosts><comment>secscan</comment><port_list id=\"%s\"/></create_target>",
			esc(name), esc(host), esc(pl))
	}
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return "", fmt.Errorf("create_target: %w", err)
	}
	if err := raw.ok(); err != nil {
		return "", fmt.Errorf("create_target: %w", err)
	}
	if raw.ID == "" {
		return "", fmt.Errorf("create_target: пустой id")
	}
	return raw.ID, nil
}

func (c *gmpClient) createTask(ctx context.Context, name, configID, targetID string) (string, error) {
	p := fmt.Sprintf("<create_task><name>%s</name><comment>secscan</comment><config id=\"%s\"/><target id=\"%s\"/></create_task>",
		esc(name), esc(configID), esc(targetID))
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return "", fmt.Errorf("create_task: %w", err)
	}
	if err := raw.ok(); err != nil {
		return "", fmt.Errorf("create_task: %w", err)
	}
	if raw.ID == "" {
		return "", fmt.Errorf("create_task: пустой id")
	}
	return raw.ID, nil
}

func (c *gmpClient) startTask(ctx context.Context, taskID string) error {
	p := fmt.Sprintf("<start_task task_id=\"%s\"/>", esc(taskID))
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return fmt.Errorf("start_task: %w", err)
	}
	return raw.ok()
}

// taskStatus возвращает статус и прогресс задачи.
func (c *gmpClient) taskStatus(ctx context.Context, taskID string) (status, progress string, err error) {
	p := fmt.Sprintf("<get_tasks task_id=\"%s\"/>", esc(taskID))
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return "", "", fmt.Errorf("get_tasks: %w", err)
	}
	if err := raw.ok(); err != nil {
		return "", "", err
	}
	var list struct {
		Tasks []struct {
			ID       string `xml:"id,attr"`
			Status   string `xml:"status"`
			Progress string `xml:"progress"`
		} `xml:"task"`
	}
	if err := parseInner(raw.Inner, &list); err != nil {
		return "", "", fmt.Errorf("get_tasks: parse: %w", err)
	}
	for _, t := range list.Tasks {
		if t.ID == taskID {
			return strings.TrimSpace(t.Status), strings.TrimSpace(t.Progress), nil
		}
	}
	return "", "", nil // задача ещё не видна — считаем «запускается»
}

func (c *gmpClient) getResults(ctx context.Context, taskID string) ([]gmpResult, error) {
	p := fmt.Sprintf("<get_results task_id=\"%s\" ignore_pagination=\"1\"/>", esc(taskID))
	raw, err := c.cmd(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("get_results: %w", err)
	}
	if err := raw.ok(); err != nil {
		return nil, err
	}
	var list struct {
		Results []gmpResult `xml:"result"`
	}
	if err := parseInner(raw.Inner, &list); err != nil {
		return nil, fmt.Errorf("get_results: parse: %w", err)
	}
	return list.Results, nil
}

func (c *gmpClient) deleteTask(taskID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := fmt.Sprintf("<delete_task task_id=\"%s\" ultimate=\"1\"/>", esc(taskID))
	if raw, err := c.cmd(ctx, p); err == nil {
		_ = raw.ok()
	}
}

func (c *gmpClient) deleteTarget(targetID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := fmt.Sprintf("<delete_target target_id=\"%s\" ultimate=\"1\"/>", esc(targetID))
	if raw, err := c.cmd(ctx, p); err == nil {
		_ = raw.ok()
	}
}

// ---------- результаты OpenVAS ----------

type gmpResult struct {
	ID          string `xml:"id,attr"`
	Name        string `xml:"name"`
	Host        string `xml:"host"`
	Port        string `xml:"port"`
	Severity    string `xml:"severity"`
	Threat      string `xml:"threat"`
	Description string `xml:"description"`
	NVT         struct {
		OID      string `xml:"oid,attr"`
		Name     string `xml:"name"`
		CVE      string `xml:"cve"`
		CvssBase string `xml:"cvss_base"`
		Tags     string `xml:"tags"`
	} `xml:"nvt"`
}

// tagsValue вытаскивает значение ключа из tags-строки gvmd
// (формат: key=value|key=value|...; внутри значения — до ;solution_type=).
func tagsValue(tags, key string) string {
	for _, chunk := range strings.Split(tags, "|") {
		chunk = strings.TrimSpace(chunk)
		if !strings.HasPrefix(chunk, key+"=") {
			continue
		}
		v := chunk[len(key)+1:]
		if i := strings.Index(v, ";"+key+"_"); i >= 0 { // напр. solution_type=
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// openvasScan запускает скан OpenVAS (конфиг «Full and fast») цели-хоста
// и возвращает находки. progress вызывается при смене статуса скана.
func openvasScan(ctx context.Context, cfg *Config, jobID, host string, progress func(string)) ([]Finding, error) {
	progress("openvas: подключение к gvmd (" + cfg.GmpSocket + ")")
	c, err := dialGMP(ctx, cfg.GmpSocket)
	if err != nil {
		return nil, fmt.Errorf("gvmd недоступен: %w", err)
	}
	defer c.close()

	if err := c.authenticate(ctx, cfg.GmpUser, cfg.GmpPass); err != nil {
		return nil, err
	}

	configID, configName, err := c.pickConfig(ctx)
	if err != nil {
		return nil, err
	}

	name := "secscan-" + jobID
	targetID, err := c.createTarget(ctx, name, host)
	if err != nil {
		return nil, err
	}
	defer c.deleteTarget(targetID)

	taskID, err := c.createTask(ctx, name, configID, targetID)
	if err != nil {
		return nil, err
	}
	defer c.deleteTask(taskID)

	if err := c.startTask(ctx, taskID); err != nil {
		return nil, fmt.Errorf("start_task: %w", err)
	}
	progress("openvas: скан запущен («" + configName + "»), ждём завершения")

	// опрос статуса до терминального состояния
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		st, prog, err := c.taskStatus(ctx, taskID)
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(st) {
		case "done":
			goto results
		case "stopped", "failed", "internal error", "deleted":
			return nil, fmt.Errorf("задача OpenVAS завершилась статусом %q", st)
		case "running", "requested", "queued", "new", "":
			if prog != "" && prog != "0" && st != "" {
				progress("openvas: сканирование («" + configName + "», " + prog + "%)")
			}
		}
		t := time.NewTimer(gmpPollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}

results:
	progress("openvas: сбор результатов")
	results, err := c.getResults(ctx, taskID)
	if err != nil {
		return nil, err
	}
	return resultsToFindings(results), nil
}

func resultsToFindings(results []gmpResult) []Finding {
	var out []Finding
	for _, r := range results {
		sev, cvss := parseOpenvasSeverity(r.Severity, r.NVT.CvssBase)
		if cvss <= 0 {
			continue // log-записи (0.0) — мусор для отчёта об уязвимостях
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = strings.TrimSpace(r.NVT.Name)
		}
		if name == "" {
			name = "Уязвимость (OpenVAS)"
		}
		port, proto := parseOpenvasPort(r.Port)
		desc := strings.TrimSpace(r.Description)
		if s := tagsValue(r.NVT.Tags, "summary"); s != "" {
			desc = s
		}
		rem := tagsValue(r.NVT.Tags, "solution")
		if rem == "" {
			rem = "Обновите затронутый продукт до актуальной версии или примените рекомендации производителя."
		}
		f := Finding{
			ID:          openvasFindingID(r),
			Source:      "openvas",
			Severity:    sev,
			CVSS:        cvss,
			CVE:         firstCVE(r.NVT.CVE),
			Host:        strings.TrimSpace(r.Host),
			Port:        port,
			Protocol:    proto,
			Title:       name,
			Description: desc,
			Remediation: rem,
			Confidence:  strings.TrimSpace(r.Threat),
		}
		if f.Host == "" {
			f.Host = "—"
		}
		out = append(out, f)
	}
	return out
}

// parseOpenvasSeverity возвращает severity и числовой CVSS.
func parseOpenvasSeverity(sevText, cvssText string) (Severity, float64) {
	cvss := 0.0
	for _, s := range []string{sevText, cvssText} {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			cvss = v
			break
		}
	}
	if cvss <= 0 {
		return SevInfo, 0
	}
	return sevFromCVSS(cvss), cvss
}

// parseOpenvasPort разбирает "80/tcp" -> (80, "tcp").
func parseOpenvasPort(s string) (int, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ""
	}
	parts := strings.SplitN(s, "/", 2)
	port := 0
	if n, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
		port = n
	}
	proto := ""
	if len(parts) == 2 {
		proto = parts[1]
	}
	return port, proto
}

func firstCVE(s string) string {
	for _, c := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		c = strings.ToUpper(strings.TrimSpace(c))
		if strings.HasPrefix(c, "CVE-") {
			return c
		}
	}
	return ""
}

func openvasFindingID(r gmpResult) string {
	if oid := strings.TrimSpace(r.NVT.OID); oid != "" {
		return "openvas-" + oid
	}
	if cve := firstCVE(r.NVT.CVE); cve != "" {
		return "openvas-" + strings.ToLower(cve)
	}
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = r.NVT.Name
	}
	return "openvas-" + slug(name)
}
