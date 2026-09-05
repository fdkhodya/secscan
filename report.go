package main

import (
	"embed"
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
