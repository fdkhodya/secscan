package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store — простое файловое хранилище задач (JSON в data/jobs/<id>.json).
type Store struct {
	dir     string
	dataDir string
	mu      sync.Mutex
}

func (s *Store) settingsPath() string { return filepath.Join(s.dataDir, "settings.json") }

// LoadSettings читает настройки; при отсутствии файла возвращает defaults.
func (s *Store) LoadSettings(def Settings) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.settingsPath())
	if err != nil {
		return def, nil
	}
	var out Settings
	if err := json.Unmarshal(b, &out); err != nil {
		return def, nil
	}
	return out, nil
}

func (s *Store) SaveSettings(set Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.settingsPath())
}

func NewStore(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "jobs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir, dataDir: dataDir}, nil
}

func (s *Store) jobPath(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *Store) SaveJob(j *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.jobPath(j.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.jobPath(j.ID))
}

func (s *Store) LoadJob(id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.jobPath(id))
	if err != nil {
		return nil, err
	}
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// DeleteJob удаляет файл задачи; отсутствующая задача — не ошибка.
func (s *Store) DeleteJob(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.jobPath(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (s *Store) ListJobs() ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var jobs []*Job
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var j Job
		if err := json.Unmarshal(b, &j); err == nil {
			jobs = append(jobs, &j)
		}
	}
	sort.Slice(jobs, func(i, k int) bool { return jobs[i].CreatedAt > jobs[k].CreatedAt })
	return jobs, nil
}

func nowRFC() string { return time.Now().Format(time.RFC3339) }

func newJobID() string {
	return fmt.Sprintf("%s-%06d", time.Now().Format("20060102-150405"), time.Now().Nanosecond()/1000)
}
