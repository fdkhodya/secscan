package main

import (
	"strings"
	"testing"
)

// Словарь переводов ZAP: все записи заполнены, известные правила переведены.
func TestZapI18n(t *testing.T) {
	if len(zapI18nMap) < 15 {
		t.Fatalf("словарь подозрительно мал: %d записей", len(zapI18nMap))
	}
	for name, tr := range zapI18nMap {
		if strings.TrimSpace(tr.Title) == "" {
			t.Errorf("пустой Title у %q", name)
		}
		if strings.TrimSpace(tr.Desc) == "" {
			t.Errorf("пустой Desc у %q", name)
		}
		if strings.TrimSpace(tr.Sol) == "" {
			t.Errorf("пустой Sol у %q", name)
		}
		// тексты должны быть русскими (содержать кириллицу)
		if !hasCyrillic(tr.Title) || !hasCyrillic(tr.Desc) || !hasCyrillic(tr.Sol) {
			t.Errorf("не русский текст у %q", name)
		}
	}
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if r >= 0x0400 && r <= 0x04FF {
			return true
		}
	}
	return false
}

func TestZapI18nKnown(t *testing.T) {
	tr, ok := zapI18nFor("Timestamp Disclosure - Unix")
	if !ok || tr.Title != "Раскрытие временной метки — Unix" {
		t.Errorf("Timestamp Disclosure: %+v ok=%v", tr, ok)
	}
	if _, ok := zapI18nFor("No Such Rule In ZAP"); ok {
		t.Error("несуществующее правило не должно быть в словаре")
	}
}
