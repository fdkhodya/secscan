package main

import "testing"

// Разбор JSON testssl.sh (вложенные объекты {id,severity,finding}).
func TestParseSSLReport(t *testing.T) {
	jsonSample := `{
	  "scanTime": "2026-09-05 19:25",
	  "scanResult": [
	    {
	      "targetHost": "127.0.0.1",
	      "protocols": [
	        {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
	        {"id": "TLS1", "severity": "INFO", "finding": "not offered"},
	        {"id": "TLS1_1", "severity": "MEDIUM", "finding": "offered"}
	      ],
	      "serverDefaults": [
	        {"id": "cert_chain_of_trust", "severity": "CRITICAL", "finding": "failed (self signed)."}
	      ],
	      "headerResponse": [
	        {"id": "HSTS", "severity": "LOW", "finding": "no HSTS header"}
	      ]
	    }
	  ]
	}`
	findings, err := parseSSLReport([]byte(jsonSample), "https://127.0.0.1:8443")
	if err != nil {
		t.Fatalf("parseSSLReport: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("ожидалось 3 находки (INFO/OK пропускаются), получено %d", len(findings))
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	if f, ok := byID["ssl-cert-chain-of-trust"]; !ok || f.Severity != SevCritical {
		t.Errorf("cert_chain_of_trust: %+v", byID["ssl-cert-chain-of-trust"])
	}
	if f, ok := byID["ssl-tls1-1"]; !ok || f.Severity != SevMedium {
		t.Errorf("TLS1_1: %+v", byID["ssl-tls1-1"])
	}
	if f, ok := byID["ssl-hsts"]; !ok || f.Severity != SevLow || f.Port != 8443 {
		t.Errorf("HSTS: %+v port=%d", byID["ssl-hsts"], f.Port)
	}
}

// Маппинг severity nuclei и сборка находки.
func TestNucleiSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SevCritical, "high": SevHigh, "medium": SevMedium,
		"low": SevLow, "info": SevInfo, "unknown": SevInfo,
	}
	for in, want := range cases {
		got, ok := nucleiSeverity(in)
		if !ok || got != want {
			t.Errorf("nucleiSeverity(%q) = %v/%v", in, got, ok)
		}
	}
	if _, ok := nucleiSeverity(""); ok {
		t.Error("пустая severity не должна приниматься")
	}
}
