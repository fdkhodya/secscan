package main

// Сигнатурный веб-сканер nuclei (projectdiscovery) — лёгкая замена
// тяжёлому OpenVAS/Greenbone: тысячи шаблонов уязвимостей, запускается
// разовым docker-контейнером, шаблоны кэшируются в data/nuclei-templates.

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// nucleiStageTimeout — общий бюджет этапа nuclei на задачу.
const nucleiStageTimeout = 60 * time.Minute

// maxNucleiFindings — верхняя граница находок nuclei на задачу.
const maxNucleiFindings = 400

type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	MatchedAt   string `json:"matched-at"`
	MatcherName string `json:"matcher-name"`
	Type        string `json:"type"`
	Info        struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Remediation    string `json:"remediation"`
		Classification struct {
			CVEID     []string `json:"cve-id"`
			CVSSScore float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// nucleiScan запускает nuclei по списку веб-целей и собирает находки.
func nucleiScan(ctx context.Context, cfg *Config, jobID string, targets []string, progress func(string)) ([]Finding, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("нет целей")
	}
	workDir := filepath.Join(cfg.HostDataDir, "work", jobID)
	if err := os.MkdirAll(workDir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(workDir, 0o777)

	// шаблоны nuclei кэшируем между запусками
	tmplDir := filepath.Join(cfg.HostDataDir, "nuclei-templates")
	if err := os.MkdirAll(tmplDir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(tmplDir, 0o777)

	empty, err := dirEmpty(tmplDir)
	if err != nil {
		return nil, err
	}
	if empty {
		progress("nuclei: скачивание шаблонов (первый запуск)")
		// nuclei v3 не ставит шаблоны в пустой каталог сам — качаем и
		// распаковываем архив напрямую с GitHub
		if err := installNucleiTemplates(ctx, tmplDir); err != nil {
			return nil, fmt.Errorf("nuclei: не удалось скачать шаблоны: %w", err)
		}
	}

	outFile := filepath.Join(workDir, "nuclei.jsonl")
	_ = os.Remove(outFile)
	mounts := []string{tmplDir + ":/root/nuclei-templates", workDir + ":/out"}
	args := []string{
		"-jsonl", "-silent", "-nc",
		"-c", "25", "-timeout", "10", "-retries", "1",
		"-t", "/root/nuclei-templates",
		"-o", "/out/nuclei.jsonl",
	}
	for _, u := range targets {
		args = append(args, "-u", u)
	}
	_, errOut, err := runDocker(ctx, cfg.NucleiImage, cfg.DockerNet, mounts, args)
	if err != nil {
		// nuclei пишет результаты по мере работы; при ошибке файл может
		// уже существовать — парсим его, иначе возвращаем ошибку
		if _, statErr := os.Stat(outFile); statErr != nil {
			return nil, fmt.Errorf("nuclei: %v: %s", err, tail(errOut, 1500))
		}
	}
	f, err := os.Open(outFile)
	if err != nil {
		return nil, fmt.Errorf("nuclei: результаты не созданы: %w", err)
	}
	defer f.Close()

	var out []Finding
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 2<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}
		sev, ok := nucleiSeverity(nr.Info.Severity)
		if !ok {
			continue
		}
		// один шаблон может дать несколько матчей (разные matcher-name) — это
		// разные проблемы, оставляем все; точные дубли отбрасываем
		key := nr.TemplateID + "|" + nr.MatchedAt + "|" + nr.MatcherName
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, nucleiFinding(nr, sev))
		if len(out) >= maxNucleiFindings {
			break
		}
	}
	return out, nil
}

func nucleiSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical, true
	case "high":
		return SevHigh, true
	case "medium":
		return SevMedium, true
	case "low":
		return SevLow, true
	case "info", "unknown":
		return SevInfo, true
	}
	return SevInfo, false
}

func nucleiFinding(nr nucleiResult, sev Severity) Finding {
	title := strings.TrimSpace(nr.Info.Name)
	if title == "" {
		title = nr.TemplateID
	}
	desc := strings.TrimSpace(nr.Info.Description)
	if r := []rune(desc); len(r) > 600 {
		desc = string(r[:600]) + "…"
	}
	rem := strings.TrimSpace(nr.Info.Remediation)
	if rem == "" {
		rem = "Изучите вывод шаблона nuclei (см. доказательства) и устраните уязвимость согласно рекомендациям производителя."
	}
	host := ""
	if u, err := url.Parse(nr.MatchedAt); err == nil {
		host = u.Hostname()
	}
	if host == "" {
		host = nr.MatchedAt
	}
	var cve string
	if len(nr.Info.Classification.CVEID) > 0 {
		cve = nr.Info.Classification.CVEID[0]
	}
	ev := "шаблон: " + nr.TemplateID + " — " + nr.MatchedAt
	if nr.MatcherName != "" {
		ev += " (матчер: " + nr.MatcherName + ")"
	}
	f := Finding{
		ID:          "nuclei-" + nr.TemplateID + "-" + shortHash(nr.MatchedAt+nr.MatcherName),
		Source:      "nuclei",
		Severity:    sev,
		CVSS:        nr.Info.Classification.CVSSScore,
		CVE:         cve,
		Host:        host,
		URL:         nr.MatchedAt,
		Title:       title,
		Description: desc,
		Remediation: rem,
		Evidence:    ev,
		Confidence:  "nuclei/" + nr.Type,
	}
	return f
}

func shortHash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%08x", h.Sum32())
}

func dirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// installNucleiTemplates скачивает архив nuclei-templates (GitHub main) и
// распаковывает в tmplDir. Первый компонент путей архива отбрасывается.
func installNucleiTemplates(ctx context.Context, tmplDir string) error {
	const zipURL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "secscan/1.0")
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d от %s", resp.StatusCode, zipURL)
	}
	tmp, err := os.CreateTemp("", "nuclei-tpl-*.zip")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := f.Name
		// отбрасываем корневую папку архива (nuclei-templates-main/...)
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" {
			continue
		}
		if strings.Contains(name, "..") {
			continue // защита от zip-slip
		}
		target := filepath.Join(tmplDir, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
