package main

import (
	"bytes"
	"embed"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

//go:embed assets/fonts/DejaVuSans.ttf assets/fonts/DejaVuSans-Bold.ttf
var fontsFS embed.FS

var sevColor = map[Severity][3]int{
	SevCritical: {185, 28, 28},
	SevHigh:     {234, 88, 12},
	SevMedium:   {202, 138, 4},
	SevLow:      {8, 145, 178},
	SevInfo:     {100, 116, 139},
}

func fontBytes(name string) []byte {
	b, err := fontsFS.ReadFile("assets/fonts/" + name)
	if err != nil {
		panic(err) // шрифты вшиты в бинарь — сбой невозможен при сборке
	}
	return b
}

// exportPDF собирает PDF-отчёт (A4, кириллица через DejaVu).
func exportPDF(j *Job) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 18)
	pdf.AddPage()
	pdf.AddUTF8FontFromBytes("reg", "", fontBytes("DejaVuSans.ttf"))
	pdf.AddUTF8FontFromBytes("bold", "", fontBytes("DejaVuSans-Bold.ttf"))

	// Шапка
	pdf.SetFont("bold", "", 16)
	pdf.SetTextColor(30, 41, 59)
	pdf.CellFormat(0, 8, "secscan — отчёт о сканировании", "", 1, "L", false, 0, "")
	pdf.SetFont("reg", "", 11)
	pdf.SetTextColor(71, 85, 105)
	meta := []string{
		fmt.Sprintf("Цель: %s", j.Target),
		fmt.Sprintf("ID: %s   ·   статус: %s   ·   создан: %s", j.ID, j.Status, formatTS(j.CreatedAt)),
	}
	if j.DoneAt != "" {
		meta = append(meta, "Завершён: "+formatTS(j.DoneAt))
	}
	if j.Error != "" {
		meta = append(meta, "Ошибки: "+j.Error)
	}
	for _, m := range meta {
		pdf.CellFormat(0, 5.5, m, "", 1, "L", false, 0, "")
	}
	counts := j.SummaryCount()
	var parts []string
	for _, s := range reportOrder {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", s.Label(), n))
		}
	}
	if len(parts) == 0 {
		parts = []string{"находок нет"}
	}
	pdf.Ln(2)
	pdf.SetFont("reg", "", 10.5)
	pdf.CellFormat(0, 6, "Сводка: "+strings.Join(parts, "   ·   "), "", 1, "L", false, 0, "")
	pdf.Ln(3)

	rows := j.SortedFindings()
	if len(rows) == 0 {
		pdf.SetFont("reg", "", 12)
		pdf.SetTextColor(100, 116, 139)
		pdf.CellFormat(0, 8, "Находок нет.", "", 1, "L", false, 0, "")
	} else {
		for i, f := range rows {
			col := sevColor[f.Severity]
			if pdf.GetY() > 255 {
				pdf.AddPage()
			}
			// заголовок находки
			pdf.SetFont("bold", "", 12)
			pdf.SetTextColor(col[0], col[1], col[2])
			sevTxt := fmt.Sprintf("[%s]", f.Severity.Label())
			pdf.CellFormat(0, 6.5, fmt.Sprintf("%d. %s %s", i+1, sevTxt, f.Title), "", 1, "L", false, 0, "")
			// мета-строка
			pdf.SetFont("reg", "", 9)
			pdf.SetTextColor(100, 116, 139)
			src := f.Source
			if f.CVE != "" {
				src += " · " + f.CVE
			}
			if f.CVSS > 0 {
				src += fmt.Sprintf(" · CVSS %.1f", f.CVSS)
			}
			if f.Host != "" {
				src += fmt.Sprintf(" · %s", f.Host)
				if f.Port > 0 {
					src += fmt.Sprintf(":%d", f.Port)
				}
			}
			if f.URL != "" {
				src += " · " + f.URL
			}
			pdf.CellFormat(0, 5, src, "", 1, "L", false, 0, "")
			// тело
			pdf.SetFont("reg", "", 10)
			pdf.SetTextColor(30, 41, 59)
			pdfLnWrapped(pdf, "Описание: "+cleanText(f.Description))
			if f.Remediation != "" {
				pdfLnWrapped(pdf, "Как исправить: "+cleanText(f.Remediation))
			}
			if f.Evidence != "" {
				pdf.SetFont("reg", "", 8.5)
				pdf.SetTextColor(100, 116, 139)
				pdfLnWrapped(pdf, "Доказательства: "+cleanText(truncate(f.Evidence, 600)))
				pdf.SetFont("reg", "", 10)
				pdf.SetTextColor(30, 41, 59)
			}
			pdf.Ln(2)
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pdfLnWrapped(pdf *fpdf.Fpdf, text string) {
	text = strings.ReplaceAll(text, "\r", " ")
	pdf.MultiCell(0, 5, text, "", "L", false)
}

func cleanText(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
