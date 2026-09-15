package main

// Severity — уровень критичности находки.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var severityLabels = map[Severity]string{
	SevCritical: "Критично",
	SevHigh:     "Высокая",
	SevMedium:   "Средняя",
	SevLow:      "Низкая",
	SevInfo:     "Информация",
}

// rank используется для сортировки: от самых критичных к менее критичным.
func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func (s Severity) Label() string {
	if l, ok := severityLabels[s]; ok {
		return l
	}
	return string(s)
}

func sevFromCVSS(cvss float64) Severity {
	switch {
	case cvss >= 9.0:
		return SevCritical
	case cvss >= 7.0:
		return SevHigh
	case cvss >= 4.0:
		return SevMedium
	case cvss > 0:
		return SevLow
	}
	return SevInfo
}

// Finding — единая находка любого сканера.
type Finding struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"` // nmap | zap | nuclei | ssl
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Host        string   `json:"host,omitempty"`
	Port        int      `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	URL         string   `json:"url,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Evidence    string   `json:"evidence,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
}

// Job — одна задача сканирования.
type Job struct {
	ID        string `json:"id"`
	Target    string `json:"target"` // что ввёл пользователь (ip/домен/url)
	Host      string `json:"host"`   // хост для nmap
	URL       string `json:"url,omitempty"`
	Status    string `json:"status"` // queued|running|done|error
	Stage     string `json:"stage,omitempty"`
	Error     string `json:"error,omitempty"`
	CreatedAt string `json:"created_at"`
	StartedAt string `json:"started_at,omitempty"`
	DoneAt    string `json:"done_at,omitempty"`
	// Stages — статусы этапов (все виды проверок выполняются всегда):
	// tcp, udp, zap, ssl, nuclei → pending|running|done|error.
	Stages   map[string]string `json:"stages,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
}

// SummaryCount возвращает число находок по каждой критичности.
func (j *Job) SummaryCount() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range j.Findings {
		m[f.Severity]++
	}
	return m
}

// SortedFindings — находки от самых критичных к менее критичным.
func (j *Job) SortedFindings() []Finding {
	out := append([]Finding(nil), j.Findings...)
	// стабильная сортировка: критичность -> cvss -> заголовок
	for i := 1; i < len(out); i++ {
		for k := i; k > 0 && less(out[k], out[k-1]); k-- {
			out[k], out[k-1] = out[k-1], out[k]
		}
	}
	return out
}

func less(a, b Finding) bool {
	if a.Severity.rank() != b.Severity.rank() {
		return a.Severity.rank() > b.Severity.rank()
	}
	if a.CVSS != b.CVSS {
		return a.CVSS > b.CVSS
	}
	return a.Title < b.Title
}
