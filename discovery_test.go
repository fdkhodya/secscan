package main

import (
	"reflect"
	"testing"
)

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"music.fdkh.ru": "fdkh.ru",
		"fdkh.ru":       "fdkh.ru",
		"a.b.c.d.co.uk": "co.uk", // ограничение: две последние метки
		"127.0.0.1":     "0.1",
	}
	for in, want := range cases {
		if got := baseDomain(in); got != want {
			t.Errorf("baseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeURLs(t *testing.T) {
	in := []string{"http://a.ru", "http://a.ru", "https://b.ru", "", "http://a.ru"}
	got := mergeURLs(in)
	want := []string{"http://a.ru", "https://b.ru"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeURLs = %v, want %v", got, want)
	}
	// лимит maxZapTargets
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, "http://s"+string(rune('a'+i))+".ru")
	}
	if got := mergeURLs(many); len(got) != maxZapTargets {
		t.Errorf("лимит не работает: %d", len(got))
	}
}

func TestPortOpen(t *testing.T) {
	if !portOpen([]int{80, 443, 8080}, 443) {
		t.Error("443 должен быть найден")
	}
	if portOpen([]int{80, 8080}, 443) {
		t.Error("443 не должен быть найден")
	}
}
