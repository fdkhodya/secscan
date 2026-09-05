package main

// Тест GMP-клиента на mock-сервере unix-сокета: проверяет фрейминг
// запрос/ответ и разбор XML-ответов gvmd (конфиги, статус задачи, результаты)
// без живого Greenbone-стека.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockGvmd отвечает на GMP-запросы скриптовыми ответами.
func mockGvmd(t *testing.T, socket string) {
	t.Helper()
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var taskPolls atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				for {
					req, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					resp := ""
					switch {
					case strings.Contains(req, "<authenticate>"):
						resp = `<authenticate_response status="200" status_text="OK"/>`
					case strings.Contains(req, "<get_configs/>"):
						resp = `<get_configs_response status="200" status_text="OK"><config id="cfg-discovery"><name>Discovery</name></config><config id="cfg-fullfast"><name>Full and fast</name></config></get_configs_response>`
					case strings.Contains(req, "<get_port_lists/>"):
						resp = `<get_port_lists_response status="200" status_text="OK"><port_list id="pl-iana"><name>All IANA assigned TCP</name></port_list></get_port_lists_response>`
					case strings.Contains(req, "<create_target>"):
						resp = `<create_target_response status="201" status_text="OK, created" id="target-1"/>`
					case strings.Contains(req, "<create_task>"):
						resp = `<create_task_response status="201" status_text="OK, created" id="task-1"/>`
					case strings.Contains(req, "<start_task"):
						resp = `<start_task_response status="202" status_text="OK, started" id="report-1"/>`
					case strings.Contains(req, "<get_tasks"):
						n := taskPolls.Add(1)
						if n < 2 {
							resp = `<get_tasks_response status="200" status_text="OK"><task id="task-1"><status>Running</status><progress>45</progress></task></get_tasks_response>`
						} else {
							resp = `<get_tasks_response status="200" status_text="OK"><task id="task-1"><status>Done</status><progress>100</progress></task></get_tasks_response>`
						}
					case strings.Contains(req, "<get_results"):
						resp = `<get_results_response status="200" status_text="OK">` +
							`<result id="r1"><name>Vuln X</name><host>192.168.7.7</host><port>443/tcp</port><severity>9.8</severity><threat>Critical</threat>` +
							`<nvt oid="1.3.6.1.4.1.25623.1.0.100001"><name>NVT Vuln X</name><cve>CVE-2024-1234</cve><cvss_base>9.8</cvss_base>` +
							`<tags>cvss_base_vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H|solution=Обновите продукт;solution_type=VendorFix|summary=Краткое описание уязвимости</tags></nvt>` +
							`<description>Длинное описание из NVT</description></result>` +
							`<result id="r2"><name>Log entry</name><host>192.168.7.7</host><port>general/tcp</port><severity>0</severity><threat>Log</threat>` +
							`<nvt oid="1.3.6.1.4.1.25623.1.0.999999"><name>NVT Log</name><cvss_base>0</cvss_base><tags>summary=просто лог</tags></nvt></result>` +
							`</get_results_response>`
					case strings.Contains(req, "<delete_task"):
						resp = `<delete_task_response status="200" status_text="OK"/>`
					case strings.Contains(req, "<delete_target"):
						resp = `<delete_target_response status="200" status_text="OK"/>`
					default:
						resp = fmt.Sprintf(`<command_response status="400" status_text="unexpected: %s"/>`, req)
					}
					if _, err := c.Write([]byte(resp + "\n")); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

func TestOpenvasScan(t *testing.T) {
	gmpPollInterval = 5 * time.Millisecond
	dir := t.TempDir()
	socket := filepath.Join(dir, "gvmd.sock")
	mockGvmd(t, socket)

	cfg := &Config{
		GmpSocket:      socket,
		GmpUser:        "admin",
		GmpPass:        "secret",
		OpenVASEnabled: true,
	}
	var stages []string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	findings, err := openvasScan(ctx, cfg, "job-123", "192.168.7.7", func(s string) { stages = append(stages, s) })
	if err != nil {
		t.Fatalf("openvasScan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка (log-запись с severity 0 должна отсекаться), получено %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SevCritical {
		t.Errorf("severity: %s, ожидалось critical", f.Severity)
	}
	if f.CVSS != 9.8 {
		t.Errorf("cvss: %v, ожидалось 9.8", f.CVSS)
	}
	if f.CVE != "CVE-2024-1234" {
		t.Errorf("cve: %q", f.CVE)
	}
	if f.Port != 443 || f.Protocol != "tcp" {
		t.Errorf("port/proto: %d/%q", f.Port, f.Protocol)
	}
	if f.Remediation != "Обновите продукт" {
		t.Errorf("remediation: %q", f.Remediation)
	}
	if f.Description != "Краткое описание уязвимости" {
		t.Errorf("description (должна быть из tags summary): %q", f.Description)
	}
	if f.Host != "192.168.7.7" {
		t.Errorf("host: %q", f.Host)
	}
	if len(stages) == 0 {
		t.Error("progress-колбэк не вызывался")
	}
}

func TestTagsValue(t *testing.T) {
	tags := "cvss_base_vector=AV:N/AC:L|solution=Update now;solution_type=VendorFix|summary=summary text"
	if got := tagsValue(tags, "solution"); got != "Update now" {
		t.Errorf("solution: %q", got)
	}
	if got := tagsValue(tags, "summary"); got != "summary text" {
		t.Errorf("summary: %q", got)
	}
	if got := tagsValue(tags, "none"); got != "" {
		t.Errorf("none: %q", got)
	}
}
