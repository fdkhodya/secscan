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
