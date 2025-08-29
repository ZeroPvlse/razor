package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// ISOTime accepts "" or RFC3339 like "2025-09-01T19:00:00Z".
type ISOTime struct{ time.Time }

func (t *ISOTime) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Value == "" {
		*t = ISOTime{} // zero = not set
		return nil
	}
	tt, err := time.Parse(time.RFC3339, node.Value)
	if err != nil {
		return fmt.Errorf("invalid RFC3339 time %q: %w", node.Value, err)
	}
	*t = ISOTime{tt}
	return nil
}
func (t ISOTime) IsZero() bool { return t.Time.IsZero() }

type Razor struct {
	Name   string `yaml:"name"`
	Client string `yaml:"client"`
	Scope  Scope  `yaml:"scope"`
	Limits Limits `yaml:"limits"`
	Report Report `yaml:"report"`
	Notes  Notes  `yaml:"notes"`
}

type Scope struct {
	Targets        []string   `yaml:"targets"`
	IncludePorts   []int      `yaml:"include_ports"`
	MaxHosts       int        `yaml:"max_hosts"`
	AllowIntrusive bool       `yaml:"allow_intrusive"`
	TimeWindow     TimeWindow `yaml:"time_window"`
}

type TimeWindow struct {
	Start ISOTime `yaml:"start"`
	End   ISOTime `yaml:"end"`
}

type Limits struct {
	RPSPerHost           int `yaml:"rps_per_host"`
	TotalRequestsPerHost int `yaml:"total_requests_per_host"`
	Concurrency          int `yaml:"concurrency"`
	ConnectTimeoutS      int `yaml:"connect_timeout_s"`
	RequestTimeoutS      int `yaml:"request_timeout_s"`
	Retries              int `yaml:"retries"`
}

type Report struct {
	Deliverables       []string `yaml:"deliverables"` // allowed: pdf_exec, html_tech, json_findings
	Redactions         bool     `yaml:"redactions"`
	CVSS               string   `yaml:"cvss"` // e.g. "v3.1"
	IncludeScreenshots bool     `yaml:"include_screenshots"`
	OutDir             string   `yaml:"out_dir"`
}

type Notes struct {
	StackHints []string `yaml:"stack_hints"`
	Contacts   []string `yaml:"contacts"`
	Tags       []string `yaml:"tags"`
}
