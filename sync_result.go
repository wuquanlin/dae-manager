package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

type SyncNode struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Change   string `json:"change"`
}
type SyncProvider struct {
	Name   string `json:"name"`
	Before int    `json:"before"`
	Count  int    `json:"count"`
}
type SyncResult struct {
	JobID             string         `json:"job_id"`
	Started           time.Time      `json:"started"`
	Finished          time.Time      `json:"finished"`
	State             string         `json:"state"`
	Stage             string         `json:"stage"`
	Message           string         `json:"message"`
	Error             string         `json:"error,omitempty"`
	PreviousRevision  string         `json:"previous_revision"`
	CandidateRevision string         `json:"candidate_revision"`
	ActiveRevision    string         `json:"active_revision"`
	NodesComplete     bool           `json:"nodes_complete"`
	Applied           bool           `json:"applied"`
	Validation        string         `json:"validation"`
	Nodes             []SyncNode     `json:"nodes"`
	Removed           []SyncNode     `json:"removed"`
	Providers         []SyncProvider `json:"providers"`
	Added             int            `json:"added"`
	Updated           int            `json:"updated"`
	Unchanged         int            `json:"unchanged"`
	Existing          int            `json:"existing"`
}

func syncNodes(before []Node, after []Node, complete bool, oldFingerprints map[string]string) (nodes, removed []SyncNode, added, updated, unchanged, existing int) {
	nodes = []SyncNode{}
	removed = []SyncNode{}
	old := map[string]Node{}
	for _, n := range before {
		old[n.ID] = n
	}
	seen := map[string]bool{}
	for _, n := range after {
		change := "added"
		if prior, ok := old[n.ID]; ok {
			fingerprint := prior.Fingerprint
			if fingerprint == "" {
				fingerprint = oldFingerprints[n.ID]
			}
			next := n.Fingerprint
			if next == "" && n.URI != "" {
				next = digest([]byte(n.URI))
			}
			switch {
			case prior.Type != n.Type || prior.Provider != n.Provider:
				change = "updated"
			case fingerprint == "" || next == "":
				change = "existing"
			case fingerprint != next:
				change = "updated"
			default:
				change = "unchanged"
			}
		}
		switch change {
		case "added":
			added++
		case "updated":
			updated++
		case "unchanged":
			unchanged++
		case "existing":
			existing++
		}
		seen[n.ID] = true
		nodes = append(nodes, SyncNode{n.Name, n.ID, n.Type, n.Provider, change})
	}
	if complete {
		for _, n := range before {
			if !seen[n.ID] {
				removed = append(removed, SyncNode{n.Name, n.ID, n.Type, n.Provider, "removed"})
			}
		}
	}
	return
}
func (m *Manager) storeSync(result SyncResult) {
	copy := result
	m.mu.Lock()
	m.syncResult = &copy
	if m.job.State == "running" && m.job.ID == result.JobID {
		m.job.Message = result.Message
	}
	m.mu.Unlock()
	_ = writeJSON(filepath.Join(m.Root, "last-update.json"), result)
}
func (m *Manager) lastSync() (SyncResult, error) {
	m.mu.RLock()
	var result SyncResult
	present := m.syncResult != nil
	if present {
		result = *m.syncResult
	}
	job := m.job
	m.mu.RUnlock()
	if !present {
		if e := readJSON(filepath.Join(m.Root, "last-update.json"), &result); e != nil {
			return result, fmt.Errorf("暂无拉取记录")
		}
	}
	if result.State == "running" && (job.State != "running" || job.ID != result.JobID) {
		result.State = "interrupted"
		result.Message = "上次拉取在后台进程重启前未完成，请重新拉取确认结果"
	}
	result.ActiveRevision = m.currentID()
	return result, nil
}
func (m *Manager) observeUpdate(ctx context.Context) (*SyncResult, func(string, string, Report)) {
	before, _ := m.report()
	oldFP := map[string]string{}
	if inv, e := m.inventory(ctx); e == nil {
		for _, n := range inv.Nodes {
			oldFP[n.ID] = digest([]byte(n.URI))
		}
	}
	m.mu.RLock()
	job := m.job
	m.mu.RUnlock()
	jobID := job.ID
	if job.State != "running" {
		jobID = fmt.Sprint(time.Now().UnixNano())
	}
	result := &SyncResult{JobID: jobID, Started: time.Now(), State: "running", Stage: "prepare", Message: "准备读取订阅链接", PreviousRevision: m.currentID(), ActiveRevision: m.currentID(), Nodes: []SyncNode{}, Removed: []SyncNode{}, Providers: []SyncProvider{}, Validation: "pending"}
	beforeCounts := map[string]int{}
	for _, n := range before.Nodes {
		beforeCounts[n.Provider]++
	}
	progress := func(stage, message string, report Report) {
		result.Stage = stage
		result.Message = message
		if in(stage, []string{"groups", "rules", "validate", "apply"}) {
			result.NodesComplete = true
		}
		result.Nodes, result.Removed, result.Added, result.Updated, result.Unchanged, result.Existing = syncNodes(before.Nodes, report.Nodes, result.NodesComplete, oldFP)
		counts := map[string]int{}
		for _, n := range report.Nodes {
			counts[n.Provider]++
		}
		result.Providers = []SyncProvider{}
		for _, name := range keys(func() M {
			v := M{}
			for k := range beforeCounts {
				v[k] = true
			}
			for k := range counts {
				v[k] = true
			}
			return v
		}()) {
			result.Providers = append(result.Providers, SyncProvider{name, beforeCounts[name], counts[name]})
		}
		if report.Validation != "" {
			result.Validation = report.Validation
		}
		m.storeSync(*result)
	}
	m.storeSync(*result)
	return result, progress
}
