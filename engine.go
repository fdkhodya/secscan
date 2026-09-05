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
			ZapEnabled:     cfg.ZapEnabled,
			OpenVASEnabled: cfg.OpenVASEnabled,
			Vulners:        cfg.NmapVulners,
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
	j.ScanOpenVAS = set.OpenVASEnabled
	j.ScanVulners = set.Vulners

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
	e.set(j, "running", "nmap: сканирование портов и сервисов", "")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()

	// 1) nmap
	nmapFindings, webPorts, err := nmapScan(ctx, e.cfg.NmapImage, e.cfg.DockerNet, j.Host, e.cfg.HostDataDir, j.ScanVulners)
	if err != nil {
		msg := fmt.Sprintf("этап nmap: %v", err)
		e.set(j, "running", "nmap: ошибка", msg)
	}
	if len(nmapFindings) > 0 {
		j.Findings = append(j.Findings, nmapFindings...)
		_ = e.store.SaveJob(j)
	}
	sort.Ints(webPorts)

	// 2) ZAP (если включён и есть куда сканировать)
	zapDone := false
	if j.ScanZap {
		urls := zapTargets(j, webPorts)
		if len(urls) > 0 {
			e.set(j, "running", "zap: активное сканирование веб-приложения", "")
			for _, u := range urls {
				findings, err := zapScan(ctx, e.cfg.ZapImage, e.cfg.DockerNet, e.cfg.HostDataDir, j.ID, u)
				if err != nil {
					msg := fmt.Sprintf("этап zap (%s): %v", u, err)
					e.set(j, "running", "zap: ошибка", msg)
					continue
				}
				j.Findings = append(j.Findings, findings...)
				zapDone = true
				_ = e.store.SaveJob(j)
				break // одного URL достаточно для baseline
			}
		}
	}
	if !j.ScanZap {
		e.set(j, "running", "zap: выключен переключателем", "")
	} else if !zapDone && len(webPorts) == 0 && j.URL == "" {
		e.set(j, "running", "zap: веб-сервисы не обнаружены — пропущен", "")
	}

	// 3) OpenVAS (Greenbone в том же docker-compose, профиль greenbone):
	//    GMP к gvmd по unix-сокету — отдельным контейнером-мостом больше
	//    не пользуемся. Ошибки этапа некритичны: nmap/zap-находки остаются.
	if j.ScanOpenVAS {
		switch {
		case e.cfg.GmpPass == "":
			e.set(j, "running", "openvas: включён, но не задан SECSCAN_GMP_PASS — пропущен", "")
		case !socketExists(e.cfg.GmpSocket):
			e.set(j, "running", "openvas: сокет gvmd недоступен ("+e.cfg.GmpSocket+") — стек Greenbone не запущен — пропущен", "")
		default:
			// У OpenVAS собственный бюджет: полный скан хоста идёт десятки
			// минут, nmap/zap живут в рамках общего ctx (90 мин).
			ctxOv, cancelOv := context.WithTimeout(context.Background(), 8*time.Hour)
			findings, err := openvasScan(ctxOv, e.cfg, j.ID, j.Host, func(stage string) {
				e.set(j, "running", stage, "")
			})
			cancelOv()
			if err != nil {
				e.set(j, "running", "openvas: ошибка — "+err.Error(), "")
			} else {
				j.Findings = append(j.Findings, findings...)
				_ = e.store.SaveJob(j)
			}
		}
	} else {
		e.set(j, "running", "openvas: выключен переключателем", "")
	}

	if ctx.Err() != nil {
		e.set(j, "error", "завершено по таймауту", ctx.Err().Error())
		return
	}
	if j.Error != "" && !strings.HasPrefix(j.Error, "этап zap") && strings.Contains(j.Error, "nmap") {
		e.set(j, "error", "", j.Error)
		return
	}
	e.set(j, "done", "готово", "")
}

// zapTargets выбирает URL для ZAP: явный URL или веб-порт из nmap.
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
		// рабочий каталог ZAP (best effort; в контейнере хост-пути может не быть)
		_ = os.RemoveAll(filepath.Join(e.cfg.HostDataDir, "work", id))
	}
	return n, nil
}
