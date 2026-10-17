package agent

import (
	"encoding/json"
	"time"
)

type RegisterRequest struct {
	InstanceID   string          `json:"instance_id"`
	Hostname     string          `json:"hostname"`
	AgentVersion string          `json:"agent_version"`
	SessionID    string          `json:"session_id"`
	AZ           string          `json:"az,omitempty"`
	Spec         json.RawMessage `json:"spec,omitempty"`
}

type RegisterResponse struct {
	WorkerID         string `json:"worker_id"`
	WorkerToken      string `json:"worker_token"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
}

type HeartbeatRequest struct {
	WorkerID      string         `json:"worker_id"`
	SessionID     string         `json:"session_id"`
	CurrentTaskID string         `json:"current_task_id,omitempty"`
	Status        string         `json:"status"`
	TerminationAt *time.Time     `json:"termination_at,omitempty"`
	Metrics       map[string]any `json:"metrics,omitempty"`
}

type HeartbeatResponse struct {
	Action            string     `json:"action"`
	ControlGeneration int64      `json:"control_generation"`
	Reason            string     `json:"reason,omitempty"`
	StopDeadline      *time.Time `json:"stop_deadline,omitempty"`
	StopTaskIDs       []string   `json:"stop_task_ids,omitempty"`
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
	requestSentAt     time.Time
}

type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	Host string `json:"host,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Technology struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Observation struct {
	Kind         string              `json:"kind"`
	Target       string              `json:"target"`
	IP           string              `json:"ip,omitempty"`
	Port         int                 `json:"port,omitempty"`
	Protocol     string              `json:"protocol,omitempty"`
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

type renewResponse struct {
	Action            string    `json:"action"`
	LeaseUntil        time.Time `json:"lease_until"`
	RateUntil         time.Time `json:"rate_until"`
	ServerTime        time.Time `json:"server_time"`
	ControlGeneration int64     `json:"control_generation"`
	Reason            string    `json:"reason,omitempty"`
}

type TaskError struct {
	Reason       string
	Retryable    bool
	FailureClass string
}

func (e *TaskError) Error() string { return e.Reason }
