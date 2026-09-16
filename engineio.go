package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Ввод-вывод движков-сканеров (SECSCAN_ENGINE_IO).
//
// Движки (nmap, ZAP, testssl.sh, nuclei) — разовые docker-контейнеры; файлы
// (отчёты, шаблоны) раньше монтировались из каталогов ХОСТА (SECSCAN_HOST_DATA).
// Такой путь должен существовать на хосте И быть виден docker-демону: обычный
// Linux-демон создаёт отсутствующий каталог сам, а Docker Desktop
// (macOS/Windows), rootless-docker, NAS и удалённый демон хостовые пути не
// видят — контейнер не создаётся: exit status 125 ("bind source path does not
// exist" / "Mounts denied" / "permission denied"). Поэтому по умолчанию
// работаем через docker-ТОМА: их создаёт и обслуживает сам демон, раскладка
// файлов на хосте перестаёт иметь значение.
//
//	SECSCAN_ENGINE_IO=volume (по умолчанию) — docker-тома;
//	SECSCAN_ENGINE_IO=host — прежнее поведение (каталоги SECSCAN_HOST_DATA).
const (
	ioModeVolume = "volume"
	ioModeHost   = "host"
)

// volumeMode — работаем ли через docker-тома вместо каталогов хоста.
func volumeMode(cfg *Config) bool { return cfg.EngineIO != ioModeHost }

// jobVolume — имя docker-тома с рабочими файлами задачи (отчёты ZAP/testssl).
func jobVolume(cfg *Config, jobID string) string {
	p := cfg.VolumePrefix
	if p == "" {
		p = "secscan-job-"
	}
	return p + jobID
}

// templatesVolume — постоянный том с шаблонами nuclei (переживает пересоздание
// контейнера secscan; шаблоны ставит в него сам nuclei при первом запуске).
func templatesVolume(cfg *Config) string {
	if cfg.TemplatesVolume != "" {
		return cfg.TemplatesVolume
	}
	return "secscan-templates"
}

// jobMount — спецификация монтирования рабочего каталога задачи в target.
func jobMount(cfg *Config, jobID, target string) string {
	if volumeMode(cfg) {
		return jobVolume(cfg, jobID) + ":" + target
	}
	return filepath.Join(cfg.HostDataDir, "work", jobID) + ":" + target
}

// templatesMount — спецификация монтирования каталога шаблонов nuclei.
func templatesMount(cfg *Config, target string) string {
	if volumeMode(cfg) {
		return templatesVolume(cfg) + ":" + target
	}
	return filepath.Join(cfg.HostDataDir, "nuclei-templates") + ":" + target
}

// prepareJobVolume готовит рабочее хранилище задачи: в режиме томов создаёт
// чистый том (том мог остаться от прерванного прогона), в host-режиме —
// каталог на хосте.
func prepareJobVolume(ctx context.Context, cfg *Config, jobID string) error {
	if !volumeMode(cfg) {
		workDir := filepath.Join(cfg.HostDataDir, "work", jobID)
		if err := os.MkdirAll(workDir, 0o777); err != nil {
			return err
		}
		return os.Chmod(workDir, 0o777)
	}
	vol := jobVolume(cfg, jobID)
	_, _, _ = execCmd(ctx, "docker", "volume", "rm", "-f", vol)
	if _, errOut, err := execCmd(ctx, "docker", "volume", "create", vol); err != nil {
		return fmt.Errorf("docker volume create %s: %v: %s", vol, err, collapseWS(errOut))
	}
	return nil
}

// chmodJobVolume открывает корень тома на запись: docker создаёт том
// root:root 0755, а ZAP и testssl.sh внутри контейнеров работают от uid 1000 и
// без этого не могут записать отчёт ("Permission denied: /zap/wrk/zap.json",
// "permission denied: /out/ssl.json"). Запуск идёт от root образом уже
// используемого движка — отдельного образа не тянем.
func chmodJobVolume(ctx context.Context, cfg *Config, image, jobID string) error {
	if !volumeMode(cfg) {
		return nil
	}
	vol := jobVolume(cfg, jobID)
	_, errOut, err := execCmd(ctx, "docker", "run", "--rm", "--user", "0",
		"-v", vol+":/v", "--entrypoint", "sh", image, "-c", "chmod 777 /v")
	if err != nil {
		return fmt.Errorf("подготовка тома %s: %v: %s", vol, err, collapseWS(errOut))
	}
	return nil
}

// cleanupJobVolume убирает рабочее хранилище задачи — best effort: сбой docker
// не должен мешать завершению задачи.
func cleanupJobVolume(cfg *Config, jobID string) {
	if !volumeMode(cfg) {
		_ = os.RemoveAll(filepath.Join(cfg.HostDataDir, "work", jobID))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, _ = execCmd(ctx, "docker", "volume", "rm", "-f", jobVolume(cfg, jobID))
}

// readArtifact читает файл, созданный движком (отчёт ZAP/testssl): в режиме
// томов — разовым контейнером того же образа с entrypoint cat, в host-режиме —
// прямо с диска (каталог хоста смонтирован в контейнер secscan по тому же пути).
func readArtifact(ctx context.Context, cfg *Config, image, jobID, fileName, containerPath string) ([]byte, error) {
	if !volumeMode(cfg) {
		return os.ReadFile(filepath.Join(cfg.HostDataDir, "work", jobID, fileName))
	}
	out, errOut, err := execCmd(ctx, "docker", "run", "--rm",
		"-v", jobVolume(cfg, jobID)+":"+filepath.Dir(containerPath),
		"--entrypoint", "cat", image, containerPath)
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, collapseWS(tail(errOut, 300)))
	}
	return []byte(out), nil
}

// dockerFailure собирает компактное сообщение о сбое docker-запуска:
// "exit status 125: docker: Error response from daemon: …". Причина берётся из
// строки "docker: Error …": она идёт ПОСЛЕ прогресса скачивания образа, и
// раньше UI терял её, обрезая длинный вывод pull.
func dockerFailure(err error, stdout, stderr string) string {
	reason := ""
	for _, s := range []string{stderr, stdout} {
		if i := strings.LastIndex(s, "docker: Error"); i >= 0 {
			reason = collapseWS(s[i:])
			break
		}
	}
	if reason == "" {
		// Строки "docker: Error" нет — контейнер отработал и вернул ненулевой
		// код. Суть такого сбоя печатает сам движок в stdout (например, ZAP
		// Automation Framework: "Automation plan failures: Job spider failed
		// to access URL … Connect timed out"), а в stderr идут только его
		// предупреждения. Раньше stdout отбрасывался и в UI оставалось
		// бесполезное "Failed to access summary file …" без причины.
		var parts []string
		if t := tail(collapseWS(stdout), 700); t != "" {
			parts = append(parts, t)
		}
		if t := tail(collapseWS(stderr), 400); t != "" {
			parts = append(parts, t)
		}
		reason = strings.Join(parts, " | ")
		if reason == "" && err != nil {
			reason = collapseWS(err.Error())
		}
	}
	if err == nil {
		return truncate(reason, 1200)
	}
	return truncate(fmt.Sprintf("%v: %s", err, reason), 1200)
}

// collapseWS схлопывает переводы строк и повторы пробелов: сообщения docker
// многострочные, а в задаче хранятся одной строкой.
func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// head — первые n символов строки (для логов).
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
