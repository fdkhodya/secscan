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
	dir string
	mu  sync.Mutex
}

func NewStore(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "jobs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
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

// formatTS приводит RFC3339-строку к локальному времени процесса (SECSCAN_TZ)
// в виде "02.01.2006 15:04". Непарсибельное — возвращает как есть.
func formatTS(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.In(time.Local).Format("02.01.2006 15:04")
}

func newJobID() string {
	return fmt.Sprintf("%s-%06d", time.Now().Format("20060102-150405"), time.Now().Nanosecond()/1000)
}
