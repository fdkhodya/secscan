package main

import (
	"strings"
	"testing"
)

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

// Контекст сертификата в находках ssl: CN/SAN (severity OK/INFO) не попадают
// в отчёт отдельными находками, но подставляются в cert_trust (описание) и в
// Evidence остальных проверок — видно, про какой домен речь при скане по IP.
func TestParseSSLCertContext(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string // ожидаемая подстрока в Description находки ssl-cert-trust
	}{
		{
			name: "скан по IP, CN совпадает с SAN",
			json: `{
			  "scanResult": [{
			    "targetHost": "46.146.247.228",
			    "serverDefaults": [
			      {"id": "cert_commonName", "severity": "OK", "finding": "photo.fdkh.ru"},
			      {"id": "cert_subjectAltName", "severity": "INFO", "finding": "photo.fdkh.ru"},
			      {"id": "cert_trust", "severity": "HIGH", "finding": "certificate does not match supplied URI"}
			    ]
			  }]
			}`,
			want: "запрос шёл на https://46.146.247.228:443, а сертификат выпущен для CN=photo.fdkh.ru. Доверие к сертификату проверяется по доменному имени — запустите скан по домену, например https://photo.fdkh.ru.",
		},
		{
			name: "мультидоменный SAN",
			json: `{
			  "scanResult": [{
			    "serverDefaults": [
			      {"id": "cert_commonName", "severity": "OK", "finding": "example.org"},
			      {"id": "cert_subjectAltName", "severity": "INFO", "finding": "DNS:example.org, DNS:www.example.org"},
			      {"id": "cert_trust", "severity": "HIGH", "finding": "certificate does not match supplied URI"}
			    ]
			  }]
			}`,
			want: "CN=example.org; SAN=DNS:example.org, DNS:www.example.org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := parseSSLReport([]byte(tc.json), "https://46.146.247.228:443")
			if err != nil {
				t.Fatalf("parseSSLReport: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("ожидалась 1 находка (cert_trust), получено %d", len(findings))
			}
			f := findings[0]
			if f.ID != "ssl-cert-trust" || f.Severity != SevHigh {
				t.Fatalf("не та находка: %+v", f)
			}
			if !strings.Contains(f.Description, tc.want) {
				t.Errorf("Description не содержит %q:\n%s", tc.want, f.Description)
			}
			if !strings.Contains(f.Evidence, "сертификат: CN=example.org") && tc.name == "мультидоменный SAN" {
				t.Errorf("Evidence не содержит строку сертификата:\n%s", f.Evidence)
			}
			if !strings.Contains(f.Evidence, "testssl.sh: cert_trust") {
				t.Errorf("Evidence потеряла источник:\n%s", f.Evidence)
			}
		})
	}
}
