package main

import (
	"errors"
	"strings"
	"testing"
)

// Лог ZAP, когда план Automation Framework обрывается: spider не смог открыть
// сайт (в stderr при этом только "Failed to access summary file …").
const zapUnreachableLog = `Using the Automation Framework
Automation plan failures:
	Job spider failed to access URL http://192.0.2.1 : Connect to http://192.0.2.1:80 [/192.0.2.1] failed: Connect timed out
`

func TestZapAccessFailureReason(t *testing.T) {
	reason, ok := zapAccessFailureReason(zapUnreachableLog)
	if !ok {
		t.Fatal("маркер обрыва плана не распознан")
	}
	if reason != "Connect timed out" {
		t.Fatalf("причина = %q, ожидалось \"Connect timed out\"", reason)
	}

	// обычный прогон (WARN-NEW/PASS) не должен считаться недоступностью
	if _, ok := zapAccessFailureReason("FAIL-NEW: 0\tWARN-NEW: 9\tPASS: 58\n"); ok {
		t.Fatal("обычный отчёт ZAP распознан как недоступность цели")
	}
}

func TestZapTargetUnreachableError(t *testing.T) {
	var err error = &zapTargetUnreachable{url: "http://192.0.2.1:80", reason: "Connect timed out"}
	if !strings.Contains(err.Error(), "Connect timed out") {
		t.Fatalf("в тексте ошибки нет причины: %q", err.Error())
	}
	var target *zapTargetUnreachable
	if !errors.As(err, &target) {
		t.Fatal("errors.As не распознал тип недоступной цели")
	}
	if target.reason != "Connect timed out" {
		t.Fatalf("reason = %q", target.reason)
	}
	if reason := (&zapTargetUnreachable{}).Error(); reason == "" {
		t.Fatal("пустое сообщение при отсутствии причины")
	}
}

func TestZapStageMessage(t *testing.T) {
	skips := []string{"http://46.146.247.228:80 (Connect timed out)"}
	errs := []string{"https://example.org: zap: отчёт не создан: exit status 3"}
	cases := []struct {
		name  string
		okN   int
		skips []string
		errs  []string
		want  string
	}{
		{"все сайты проверены", 2, nil, nil, "zap: проверено сайтов: 2"},
		{
			"один сайт недоступен", 1, skips, nil,
			"zap: проверено сайтов: 1; недоступны для сканера: 1 — http://46.146.247.228:80 (Connect timed out)",
		},
		{
			"недоступен и ошибка", 1, skips, errs,
			"zap: проверено сайтов: 1; недоступны для сканера: 1 — http://46.146.247.228:80 (Connect timed out); " +
				"ошибки: https://example.org: zap: отчёт не создан: exit status 3",
		},
	}
	for _, c := range cases {
		if got := zapStageMessage(c.okN, c.skips, c.errs); got != c.want {
			t.Errorf("%s: текст этапа = %q, ожидалось %q", c.name, got, c.want)
		}
	}
}
