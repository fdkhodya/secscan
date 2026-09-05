package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed web/*.html
var webFS embed.FS

type Config struct {
	Listen      string
	DataDir     string
	HostDataDir string
	User        string
	Pass        string
	NmapImage   string
	ZapImage    string
	ZapEnabled  bool
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	cfg := Config{
		Listen:      envOr("SECSCAN_LISTEN", ":8510"),
		DataDir:     envOr("SECSCAN_DATA", "./data"),
		HostDataDir: envOr("SECSCAN_HOST_DATA", ""),
		User:        envOr("SECSCAN_USER", "admin"),
		Pass:        envOr("SECSCAN_PASS", ""),
		NmapImage:   envOr("SECSCAN_NMAP_IMAGE", "instrumentisto/nmap:latest"),
		ZapImage:    envOr("SECSCAN_ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable"),
		ZapEnabled:  envOr("SECSCAN_ZAP_ENABLED", "1") != "0",
	}
	if cfg.Pass == "" {
		cfg.Pass = "admin"
		log.Printf("ВНИМАНИЕ: SECSCAN_PASS не задан, используется пароль по умолчанию admin/admin — задайте через env!")
	}
	if cfg.HostDataDir == "" {
		abs, err := filepath.Abs(cfg.DataDir)
		if err != nil {
			abs = cfg.DataDir
		}
		cfg.HostDataDir = abs
	}
	return cfg
}

var (
	idxTpl  *template.Template
	loginTpl *template.Template
)

func main() {
	cfg := loadConfig()

	store, err := NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	auth := NewAuth(cfg.User, cfg.Pass)
	eng := NewEngine(store, &cfg)
	eng.Start()

	if err := initReportTmpl(webFS); err != nil {
		log.Fatalf("report template: %v", err)
	}
	idxTpl = template.Must(template.New("index.html").ParseFS(webFS, "web/index.html"))
	loginTpl = template.Must(template.New("login.html").ParseFS(webFS, "web/login.html"))

	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil && auth.Check(c.Value) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		_ = loginTpl.Execute(w, r.URL.Query().Has("error"))
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok, ok := auth.Login(r.FormValue("user"), r.FormValue("pass"))
		if !ok {
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: 86400 * 7,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("POST /logout", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			auth.Logout(c.Value)
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))

	mux.HandleFunc("GET /", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		_ = idxTpl.Execute(w, nil)
	}))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// API
	mux.HandleFunc("POST /api/scans", auth.requireAuth(apiCreateScan(eng)))
	mux.HandleFunc("GET /api/scans", auth.requireAuth(apiListScans(store)))
	mux.HandleFunc("GET /api/scans/{id}", auth.requireAuth(apiGetScan(store)))

	// Отчёт и экспорт
	mux.HandleFunc("GET /reports/{id}", auth.requireAuth(apiReport(store)))
	mux.HandleFunc("GET /reports/{id}/export.csv", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		j, err := store.LoadJob(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		b, err := exportCSV(j)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=secscan-%s.csv", j.ID))
		_, _ = w.Write(b)
	}))
	mux.HandleFunc("GET /reports/{id}/export.pdf", auth.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		j, err := store.LoadJob(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		b, err := exportPDF(j)
		if err != nil {
			http.Error(w, "pdf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=secscan-%s.pdf", j.ID))
		_, _ = w.Write(b)
	}))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("secscan listening on %s (data: %s, host-data: %s)", cfg.Listen, cfg.DataDir, cfg.HostDataDir)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiCreateScan(eng *Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный JSON"})
			return
		}
		id, err := eng.Submit(req.Target)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
	}
}

func apiListScans(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobs, err := store.ListJobs()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, jobs)
	}
}

func apiGetScan(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := store.LoadJob(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "задача не найдена"})
			return
		}
		writeJSON(w, http.StatusOK, j)
	}
}

func apiReport(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := store.LoadJob(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := renderReport(w, j); err != nil {
			http.Error(w, fmt.Sprintf("report: %v", err), http.StatusInternalServerError)
		}
	}
}
