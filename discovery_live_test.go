package main

// Живая проверка discovery против реального IP (по умолчанию пропускается):
//   LIVE=1 go test -run TestLiveDiscover -v .
// Используется для проверки поиска сайтов цели (TLS SAN + crt.sh + резолв).
import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveDiscover(t *testing.T) {
	if os.Getenv("LIVE") == "" {
		t.Skip("LIVE=1 не задан — пропускаю сетевой тест")
	}
	host := os.Getenv("LIVE_HOST")
	if host == "" {
		host = "46.146.247.228"
	}
	cfg := &Config{Crtsh: true}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	job := &Job{Host: host}
	names := discoverSiteNames(ctx, cfg, job, []int{80, 443})
	t.Logf("найдено сайтов на %s: %d: %s", host, len(names), strings.Join(names, ", "))
	if len(names) == 0 {
		t.Fatal("discovery ничего не нашёл")
	}
}
