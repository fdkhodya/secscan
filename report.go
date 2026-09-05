package main

import (
	"bytes"
	"embed"
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"strings"
)

type reportData struct {
	Job    *Job
	Rows   []Finding
	Counts []sevCount
}

type sevCount struct {
	Sev   Severity
	Label string
	N     int
}

var reportOrder = []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

var reportFuncs = template.FuncMap{
	"sevLabel": func(s Severity) string { return s.Label() },
	"sevClass": func(s Severity) string {
		switch s {
		case SevCritical:
			return "sev-critical"
		case SevHigh:
			return "sev-high"
		case SevMedium:
			return "sev-medium"
		case SevLow:
			return "sev-low"
		default:
			return "sev-info"
		}
	},
	"join": strings.Join,
	// ts — локальное время (SECSCAN_TZ) из RFC3339-строки
	"ts": formatTS,
}

var reportTmpl *template.Template

func initReportTmpl(fs embed.FS) error {
	t, err := template.New("report.html").Funcs(reportFuncs).ParseFS(fs, "web/report.html")
	if err != nil {
		return err
	}
	reportTmpl = t
	return nil
}

// renderReport рисует HTML-отчёт: от самых критичных к менее критичным.
func renderReport(w io.Writer, j *Job) error {
	counts := j.SummaryCount()
	var cc []sevCount
	for _, s := range reportOrder {
		if n := counts[s]; n > 0 {
			cc = append(cc, sevCount{Sev: s, Label: s.Label(), N: n})
		}
	}
	if len(cc) == 0 && j.Status == "done" {
		cc = append(cc, sevCount{Sev: SevInfo, Label: "Info", N: 0})
	}
	data := reportData{Job: j, Rows: j.SortedFindings(), Counts: cc}
	if reportTmpl == nil {
		return fmt.Errorf("report template not initialized")
	}
	return reportTmpl.Execute(w, data)
}

// exportCSV формирует CSV-отчёт (UTF-8 c BOM для Excel).
func exportCSV(j *Job) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff") // BOM
	w := csv.NewWriter(&buf)
	w.Comma = ';'
	header := []string{"Критичность", "Источник", "CVE", "CVSS", "Заголовок",
		"Хост", "Порт", "URL", "Описание", "Как исправить", "Доказательства", "Уверенность"}
	if err := w.Write(header); err != nil {
		return nil, err
	}
	for _, f := range j.SortedFindings() {
		row := []string{f.Severity.Label(), f.Source, f.CVE, fmt.Sprintf("%.1f", f.CVSS),
			f.Title, f.Host, fmt.Sprintf("%d", f.Port), f.URL,
			f.Description, f.Remediation, f.Evidence, f.Confidence}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
