package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Engine — очередь задач и выполнение сканирования.
type Engine struct {
	store *Store
	cfg   *Config
	defs  Settings
	queue chan string
}

func NewEngine(store *Store, cfg *Config) *Engine {
	return &Engine{
		store: store,
		cfg:   cfg,
		defs: Settings{
			ZapEnabled:    cfg.ZapEnabled,
			NucleiEnabled: cfg.NucleiEnabled,
			UdpEnabled:    cfg.UdpEnabled,
			NseEnabled:    cfg.NseEnabled,
			Vulners:       cfg.Vulners,
			SslEnabled:    cfg.SslEnabled,
		},
		queue: make(chan string, 10),
	}
}

// Start запускает единственный воркер (сканы последовательны).
func (e *Engine) Start() {
	go func() {
		for id := range e.queue {
			e.run(id)
		}
	}()
}

// Defaults возвращает настройки по умолчанию (из env при первом запуске).
func (e *Engine) Defaults() Settings { return e.defs }

// Submit создаёт задачу и ставит её в очередь.
func (e *Engine) Submit(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("target пустой")
	}
	if !isURLTarget(target) {
		if ip := net.ParseIP(strings.Trim(target, "[]")); ip == nil {
			if _, err := net.LookupHost(target); err != nil {
				return "", fmt.Errorf("не удалось разрешить хост %q: %w", target, err)
			}
		}
	}
	j := &Job{
		ID:        newJobID(),
		Target:    target,
		Host:      resolveHost(target),
		Status:    "queued",
		Stage:     "очередь",
		CreatedAt: nowRFC(),
	}
	if isURLTarget(target) {
		j.URL = target
	}
	// снапшот включённых проверок на момент запуска
	set, _ := e.store.LoadSettings(e.defs)
	j.ScanZap = set.ZapEnabled
	j.ScanNuclei = set.NucleiEnabled
	j.ScanUdp = set.UdpEnabled
	j.ScanNse = set.NseEnabled
	j.ScanVulners = set.Vulners
	j.ScanSsl = set.SslEnabled

	if err := e.store.SaveJob(j); err != nil {
		return "", err
	}
	select {
	case e.queue <- j.ID:
	default:
		return "", fmt.Errorf("очередь переполнена, подождите")
	}
	return j.ID, nil
}

func (e *Engine) set(j *Job, status, stage string, errText string) {
	j.Status = status
	if stage != "" {
		j.Stage = stage
	}
	if errText != "" {
		j.Error = errText
	}
	switch status {
	case "running":
		j.StartedAt = nowRFC()
	case "done", "error":
		j.DoneAt = nowRFC()
	}
	if err := e.store.SaveJob(j); err != nil {
		log.Printf("save job %s: %v", j.ID, err)
	}
}

func (e *Engine) run(id string) {
	j, err := e.store.LoadJob(id)
	if err != nil {
		log.Printf("load job %s: %v", id, err)
		return
	}
	e.set(j, "running", "nmap: сканирование TCP-портов и сервисов", "")

	// Общий бюджет на «быстрые» этапы (nmap/zap/ssl/nuclei-части).
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()

	// 1) nmap TCP: порты/сервисы (+NSE: vulners и доп. скрипты по тумблерам)
	nmapFatal := false
	nmapFindings, webPorts, err := nmapScan(ctx, e.cfg, j.Host, j.ScanVulners, j.ScanNse)
	if err != nil {
		msg := fmt.Sprintf("этап nmap: %v", err)
		e.set(j, "running", "nmap: ошибка", msg)
		if len(nmapFindings) == 0 {
			nmapFatal = true // нет даже частичных результатов
		}
	}
	if len(nmapFindings) > 0 {
		j.Findings = append(j.Findings, nmapFindings...)
		_ = e.store.SaveJob(j)
	}
	sort.Ints(webPorts)

	// 2) nmap UDP (top-50 портов) — по тумблеру
	if j.ScanUdp {
		e.set(j, "running", "nmap: сканирование UDP-портов", "")
		udpFindings, err := nmapUDPScan(ctx, e.cfg.NmapImage, e.cfg.DockerNet, j.Host)
		if err != nil {
			e.set(j, "running", "nmap-udp: ошибка", fmt.Sprintf("этап nmap-udp: %v", err))
		} else if len(udpFindings) > 0 {
			j.Findings = append(j.Findings, udpFindings...)
			_ = e.store.SaveJob(j)
		}
	} else {
		e.set(j, "running", "nmap-udp: выключен переключателем", "")
	}

	// 3) ZAP: цель и все найденные на её IP сайты (http/https)
	var webURLs []string
	if j.ScanZap {
		webURLs = webTargetList(ctx, e.cfg, j, webPorts)
		if len(webURLs) > 0 {
			e.set(j, "running", fmt.Sprintf("zap: проверка сайтов — целей: %d", len(webURLs)), "")
			okN, zapErrs := 0, []string{}
			for i, u := range webURLs {
				e.set(j, "running", fmt.Sprintf("zap: сайт %d/%d — %s", i+1, len(webURLs), u), "")
				// у каждого сайта собственный бюджет; общий ctx не даёт
				// одному медленному сайту съесть время остальных
				uCtx, cancel := context.WithTimeout(ctx, zapTargetTimeout)
				findings, err := zapScan(uCtx, e.cfg.ZapImage, e.cfg.DockerNet, e.cfg.HostDataDir, j.ID, u)
				cancel()
				if err != nil {
					zapErrs = append(zapErrs, u+": "+firstLine(err.Error()))
					continue
				}
				j.Findings = append(j.Findings, findings...)
				okN++
				_ = e.store.SaveJob(j)
			}
			msg := fmt.Sprintf("zap: проверено сайтов: %d", okN)
			if len(zapErrs) > 0 {
				msg = fmt.Sprintf("zap: ок %d из %d; ошибки: %s", okN, len(webURLs), strings.Join(zapErrs, "; "))
			}
			if len(zapErrs) > 0 {
				// префикс «этап zap» — ошибки этапа не роняют задачу целиком
				e.set(j, "running", "zap: с ошибками", "этап zap: "+truncate(msg, 600))
			} else {
				e.set(j, "running", msg, "")
			}
		}
	} else {
		e.set(j, "running", "zap: выключен переключателем", "")
	}

	// 4) TLS/SSL-анализ (testssl.sh) — по https-целям
	if j.ScanSsl {
		sslURLs := sslTargetList(ctx, e.cfg, j, webPorts)
		if len(sslURLs) > 0 {
			e.set(j, "running", fmt.Sprintf("ssl: TLS/SSL-анализ — целей: %d", len(sslURLs)), "")
			sslErrs := []string{}
			for i, u := range sslURLs {
				e.set(j, "running", fmt.Sprintf("ssl: %d/%d — %s", i+1, len(sslURLs), u), "")
				uCtx, cancel := context.WithTimeout(ctx, sslTargetTimeout)
				findings, err := sslScan(uCtx, e.cfg, j.ID, i, u)
				cancel()
				if err != nil {
					sslErrs = append(sslErrs, u+": "+firstLine(err.Error()))
					continue
				}
				j.Findings = append(j.Findings, findings...)
				_ = e.store.SaveJob(j)
			}
			if len(sslErrs) > 0 {
				e.set(j, "running", "ssl: с ошибками",
					"этап ssl: "+truncate("ssl: ошибки: "+strings.Join(sslErrs, "; "), 600))
			} else {
				e.set(j, "running", fmt.Sprintf("ssl: проверено целей: %d", len(sslURLs)), "")
			}
		} else {
			e.set(j, "running", "ssl: https-сервисы не обнаружены — пропущен", "")
		}
	} else {
		e.set(j, "running", "ssl: выключен переключателем", "")
	}

	// 5) nuclei: сигнатурный веб-сканер (лёгкая замена OpenVAS)
	if j.ScanNuclei {
		nucURLs := webTargetList(ctx, e.cfg, j, webPorts)
		if len(nucURLs) > 0 {
			e.set(j, "running", fmt.Sprintf("nuclei: сигнатурный скан — целей: %d", len(nucURLs)), "")
			nucCtx, cancel := context.WithTimeout(ctx, nucleiStageTimeout)
			findings, err := nucleiScan(nucCtx, e.cfg, j.ID, nucURLs, func(stage string) {
				e.set(j, "running", stage, "")
			})
			cancel()
			if err != nil {
				e.set(j, "running", "nuclei: с ошибками", "этап nuclei: "+truncate(err.Error(), 600))
			} else {
				j.Findings = append(j.Findings, findings...)
				_ = e.store.SaveJob(j)
				e.set(j, "running", fmt.Sprintf("nuclei: проверено целей: %d", len(nucURLs)), "")
			}
		} else {
			e.set(j, "running", "nuclei: веб-сервисы не обнаружены — пропущен", "")
		}
	} else {
		e.set(j, "running", "nuclei: выключен переключателем", "")
	}

	if ctx.Err() != nil {
		e.set(j, "error", "завершено по таймауту", ctx.Err().Error())
		return
	}
	if nmapFatal {
		e.set(j, "error", "nmap: ошибка", j.Error)
		return
	}
	e.set(j, "done", "готово", "")
}

// DeleteScans удаляет завершённые задачи (done/error) и их рабочие каталоги.
// Активные (queued/running) удалять нельзя: воркер держит задачу в памяти и
// при следующем шаге пересоздаст файл.
func (e *Engine) DeleteScans(ids []string) (int, error) {
	var toDelete []string
	for _, id := range ids {
		j, err := e.store.LoadJob(id)
		if err != nil {
			continue // уже удалена
		}
		if j.Status == "queued" || j.Status == "running" {
			return 0, fmt.Errorf("задача %s ещё выполняется (%s) — удалите после завершения", id, j.Status)
		}
		toDelete = append(toDelete, id)
	}
	n := 0
	for _, id := range toDelete {
		if err := e.store.DeleteJob(id); err != nil {
			return n, err
		}
		n++
		// рабочие каталоги сканеров (best effort; в контейнере хост-пути может не быть)
		_ = os.RemoveAll(filepath.Join(e.cfg.HostDataDir, "work", id))
	}
	return n, nil
}
