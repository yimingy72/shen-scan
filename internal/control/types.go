package control

import (
	"context"
	"encoding/json"
	"time"
)

type Run struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Targets       []string  `json:"targets"`
	Modes         []string  `json:"modes"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	TaskTotal     int64     `json:"task_total"`
	TaskDone      int64     `json:"task_done"`
	TaskFailed    int64     `json:"task_failed"`
	AssetCount    int64     `json:"asset_count"`
	TargetCount   int64     `json:"target_count"`
	TargetDone    int64     `json:"target_done"`
	OpenPortCount int64     `json:"open_port_count"`
	HTTPCount     int64     `json:"http_count"`
	InputCount    int       `json:"input_count"`
	Error         string    `json:"error"`
}

type Task struct {
	ID                string          `json:"id"`
	RunID             string          `json:"run_id"`
	Type              string          `json:"type"`
	AttemptNo         int             `json:"attempt_no"`
	Payload           json.RawMessage `json:"payload"`
	LeaseUntil        time.Time       `json:"lease_until"`
	RateUntil         time.Time       `json:"rate_until"`
	ServerTime        time.Time       `json:"server_time"`
	ControlGeneration int64           `json:"control_generation"`
}

type Technology struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Observation struct {
	Kind         string              `json:"kind"`
	Target       string              `json:"target"`
	IP           string              `json:"ip"`
	Port         int                 `json:"port"`
	Protocol     string              `json:"protocol"`
	Service      string              `json:"service,omitempty"`
	Product      string              `json:"product,omitempty"`
	Version      string              `json:"version,omitempty"`
	URL          string              `json:"url,omitempty"`
	StatusCode   int                 `json:"status_code,omitempty"`
	Title        string              `json:"title,omitempty"`
	Server       string              `json:"server,omitempty"`
	Technologies []Technology        `json:"technologies,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`
	BodyExcerpt  string              `json:"body_excerpt,omitempty"`
	Banner       string              `json:"banner,omitempty"`
	RequestRaw   string              `json:"request_raw,omitempty"`
	ResponseRaw  string              `json:"response_raw,omitempty"`
	Truncated    bool                `json:"truncated,omitempty"`
	Error        string              `json:"error,omitempty"`
}

type Asset struct {
	ID         string    `json:"id"`
	RunID      string    `json:"run_id"`
	ObservedAt time.Time `json:"observed_at"`
	Observation
}

type Worker struct {
	ID            string             `json:"id"`
	InstanceID    string             `json:"instance_id"`
	Hostname      string             `json:"hostname"`
	Status        string             `json:"status"`
	AgentVersion  string             `json:"agent_version"`
	LastHeartbeat time.Time          `json:"last_heartbeat"`
	CurrentTaskID string             `json:"current_task_id,omitempty"`
	AZ            string             `json:"az,omitempty"`
	Spec          json.RawMessage    `json:"spec,omitempty"`
	Metrics       map[string]float64 `json:"metrics"`
	ActiveTasks   []WorkerTask       `json:"active_tasks"`
}

type WorkerTask struct {
	Targets []string `json:"targets"`
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Target  string   `json:"target"`
	RunID   string   `json:"run_id"`
	RunName string   `json:"run_name"`
}

type Pool struct {
	DesiredWorkers  int    `json:"desired_workers"`
	Enabled         bool   `json:"enabled"`
	Generation      int64  `json:"generation"`
	HealthyWorkers  int    `json:"healthy_workers"`
	StartingWorkers int    `json:"starting_workers"`
	DrainingWorkers int    `json:"draining_workers"`
	Provider        string `json:"provider"`
	Configured      bool   `json:"configured"`
	Error           string `json:"error"`
}

// PoolReconciler is installed by the cloud package. It must be idempotent for
// a Pool generation because retries are expected after process restarts.
type PoolReconciler func(context.Context, Pool) error
