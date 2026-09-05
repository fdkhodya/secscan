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
	queue chan string
}

func NewEngine(store *Store, cfg *Config) *Engine {
	return &Engine{
		store: store,
		cfg:   cfg,
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
		Stages: map[string]string{
			"tcp": "pending", "udp": "pending", "zap": "pending",
			"ssl": "pending", "nuclei": "pending",
		},
	}
	if isURLTarget(target) {
		j.URL = target
	}

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

// setStage обновляет статус этапа задачи (tcp|udp|zap|ssl|nuclei):
// pending|running|done|error.
func (e *Engine) setStage(j *Job, key, st string) {
	if j.Stages == nil {
		j.Stages = map[string]string{}
	}
	j.Stages[key] = st
	_ = e.store.SaveJob(j)
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

	// 1) nmap TCP: порты/сервисы + NSE (vulners CVE и доп. скрипты) — всегда
	nmapFatal := false
	nmapFindings, webPorts, err := nmapScan(ctx, e.cfg, j.Host, true, true)
	if err != nil {
		msg := fmt.Sprintf("этап nmap: %v", err)
		e.set(j, "running", "nmap: ошибка", msg)
		if len(nmapFindings) == 0 {
			nmapFatal = true // нет даже частичных результатов
		}
	}
	if nmapFatal {
		e.setStage(j, "tcp", "error")
	} else {
		e.setStage(j, "tcp", "done")
	}
	if len(nmapFindings) > 0 {
		j.Findings = append(j.Findings, nmapFindings...)
		_ = e.store.SaveJob(j)
	}
	sort.Ints(webPorts)

	// 2) nmap UDP (top-50 портов) — всегда
	e.set(j, "running", "nmap: сканирование UDP-портов", "")
	e.setStage(j, "udp", "running")
	udpFindings, err := nmapUDPScan(ctx, e.cfg.NmapImage, e.cfg.DockerNet, j.Host)
	if err != nil {
		e.set(j, "running", "nmap-udp: ошибка", fmt.Sprintf("этап nmap-udp: %v", err))
		e.setStage(j, "udp", "error")
	} else {
		e.setStage(j, "udp", "done")
		if len(udpFindings) > 0 {
			j.Findings = append(j.Findings, udpFindings...)
			_ = e.store.SaveJob(j)
		}
	}

	// 3) ZAP: цель и все найденные на её IP сайты (http/https) — всегда
	var webURLs []string
	e.setStage(j, "zap", "running")
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
			e.set(j, "running", "zap: с ошибками", "этап zap: "+truncate(msg, 600))
		} else {
			e.set(j, "running", msg, "")
		}
		if okN == 0 && len(zapErrs) > 0 {
			e.setStage(j, "zap", "error")
		} else {
			e.setStage(j, "zap", "done")
		}
	} else {
		e.set(j, "running", "zap: веб-сервисы не обнаружены — пропущен", "")
		e.setStage(j, "zap", "done")
	}

	// 4) TLS/SSL-анализ (testssl.sh) — всегда
	e.setStage(j, "ssl", "running")
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
			if len(sslErrs) >= len(sslURLs) {
				e.setStage(j, "ssl", "error")
			} else {
				e.setStage(j, "ssl", "done")
			}
		} else {
			e.set(j, "running", fmt.Sprintf("ssl: проверено целей: %d", len(sslURLs)), "")
			e.setStage(j, "ssl", "done")
		}
	} else {
		e.set(j, "running", "ssl: https-сервисы не обнаружены — пропущен", "")
		e.setStage(j, "ssl", "done")
	}

	// 5) nuclei: сигнатурный веб-сканер — всегда
	e.setStage(j, "nuclei", "running")
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
			e.setStage(j, "nuclei", "error")
		} else {
			e.setStage(j, "nuclei", "done")
			j.Findings = append(j.Findings, findings...)
			_ = e.store.SaveJob(j)
			e.set(j, "running", fmt.Sprintf("nuclei: проверено целей: %d", len(nucURLs)), "")
		}
	} else {
		e.set(j, "running", "nuclei: веб-сервисы не обнаружены — пропущен", "")
		e.setStage(j, "nuclei", "done")
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
