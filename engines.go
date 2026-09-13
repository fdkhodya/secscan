package main

// Режимы запуска движков-сканеров (SECSCAN_ENGINE_MODE):
//
//   docker (по умолчанию) — каждый движок запускается разовым
//     docker-контейнером через docker.sock хоста с --network host
//     (Linux-сервер: сканирование как с самого хоста);
//
//   local — движки запускаются обычными процессами внутри этого же
//     контейнера secscan. Нужен для Docker Desktop (macOS/Windows), где
//     docker.sock и --network host не работают: тогда всё упаковано в один
//     образ (`allinone`: nmap + ZAP + nuclei + testssl.sh) и ни
//     монтирований, ни хостовых путей не требуется.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// errEngineUnavailable — движок не установлен в образе (только local-режим).
var errEngineUnavailable = errors.New("движок не установлен в этом образе")

// LocalEngines — движки запускаются локальными процессами (режим local).
func (c *Config) LocalEngines() bool {
	return c.EngineMode == "local"
}

// engineAvailable сообщает, доступен ли движок в текущем режиме. В
// docker-режиме проверять нечего (образ тянет docker), в local-режиме
// бинарник ищется в PATH.
func (c *Config) engineAvailable(bin string) bool {
	if !c.LocalEngines() {
		return true
	}
	if bin == "" {
		return false
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// engineRun — описание одного запуска движка-сканера.
type engineRun struct {
	image  string   // образ для docker-режима
	bin    string   // программа/скрипт для local-режима (ищется в PATH)
	mounts []string // монтирования для docker-режима (в local игнорируются)
	dir    string   // рабочий каталог процесса в local-режиме
	args   []string // аргументы движка
	// dockerCmd — команда внутри образа (docker-режим). Пусто — entrypoint
	// образа уже и есть нужный сканер (nmap, testssl.sh, nuclei).
	dockerCmd string
}

// runEngine выполняет движок: локальным процессом (local) или разовым
// docker-контейнером (docker).
func (c *Config) runEngine(ctx context.Context, r engineRun) (stdout, stderr string, err error) {
	if !c.LocalEngines() {
		args := r.args
		if r.dockerCmd != "" {
			args = append([]string{r.dockerCmd}, args...)
		}
		return runDocker(ctx, r.image, c.DockerNet, r.mounts, args)
	}
	return runLocal(ctx, r.bin, r.dir, r.args)
}

// runLocal запускает движок как локальный процесс.
func runLocal(ctx context.Context, bin, dir string, args []string) (string, string, error) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", errEngineUnavailable, bin)
	}
	cmd := execCommandContext(ctx, path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var ob, eb bytes.Buffer
	cmd.Stdout = &ob
	cmd.Stderr = &eb
	err = cmd.Run()
	return ob.String(), eb.String(), err
}
