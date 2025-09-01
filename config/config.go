// package that creates and contains all scanning methods + configs
package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/defaults"
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

// read  from "*.yaml" provided by user
// and apply given defaults (this is mess btw)
func Load(path string) (*Razor, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Razor
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c.ApplyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Razor) ApplyDefaults() {
	// Limits
	if c.Limits.RPSPerHost == 0 {
		c.Limits.RPSPerHost = 2
	}
	if c.Limits.TotalRequestsPerHost == 0 {
		c.Limits.TotalRequestsPerHost = 1000
	}
	if c.Limits.Concurrency == 0 {
		c.Limits.Concurrency = 10
	}
	if c.Limits.ConnectTimeoutS == 0 {
		c.Limits.ConnectTimeoutS = 5
	}
	if c.Limits.RequestTimeoutS == 0 {
		c.Limits.RequestTimeoutS = 10
	}
	// Report
	if c.Report.CVSS == "" {
		c.Report.CVSS = "v3.1"
	}

	if len(c.Scope.IncludePorts) == 0 {
		c.Scope.IncludePorts = defaults.Ports()
	}

	// Reasonable default deliverables if none chosen
	if len(c.Report.Deliverables) == 0 {
		c.Report.Deliverables = []string{"html_tech", "json_findings"}
	}
}

func (c *Razor) validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.Client == "" {
		return errors.New("client is required")
	}

	if len(c.Scope.Targets) == 0 {
		return errors.New("target needs to be specified")
	}
	// Scope
	for _, p := range c.Scope.IncludePorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("include_ports contains invalid port: %d", p)
		}
	}
	if !c.Scope.TimeWindow.Start.IsZero() || !c.Scope.TimeWindow.End.IsZero() {
		if c.Scope.TimeWindow.Start.IsZero() || c.Scope.TimeWindow.End.IsZero() {
			return errors.New("time_window must have both start and end or be empty")
		}
		if !c.Scope.TimeWindow.End.After(c.Scope.TimeWindow.Start.Time) {
			return errors.New("time_window.end must be after time_window.start")
		}
	}

	// Limits
	if c.Limits.RPSPerHost < 0 {
		return errors.New("rps_per_host must be >= 0")
	}
	if c.Limits.TotalRequestsPerHost < 0 {
		return errors.New("total_requests_per_host must be >= 0")
	}
	if c.Limits.Concurrency <= 0 {
		return errors.New("concurrency must be > 0")
	}
	if c.Limits.ConnectTimeoutS <= 0 || c.Limits.RequestTimeoutS <= 0 {
		return errors.New("timeouts must be > 0")
	}
	if c.Limits.Retries < 0 {
		return errors.New("retries must be >= 0")
	}

	// Report
	allowed := map[string]struct{}{
		"pdf_exec": {}, "html_tech": {}, "json_findings": {},
	}
	for _, d := range c.Report.Deliverables {
		if _, ok := allowed[d]; !ok {
			return fmt.Errorf("unknown deliverable %q (allowed: pdf_exec, html_tech, json_findings)", d)
		}
	}
	if c.Report.CVSS != "v3.1" {
		return fmt.Errorf("unsupported cvss %q (only v3.1 supported here)", c.Report.CVSS)
	}
	return nil
}

func (cfg *Razor) Nmap() (*nmap.Run, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ports := SlicePortToStr(cfg.Scope.IncludePorts)

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(cfg.Scope.Targets...),
		nmap.WithPorts(ports),
		nmap.WithAggressiveScan(),  // os detection + service info + default script + trace route
		nmap.WithFragmentPackets(), // <- we go stealthy as fuck
		nmap.WithFilterHost(func(h nmap.Host) bool {
			// if port ain't open we don't want it ;3
			for idx := range h.Ports {
				if h.Ports[idx].Status() == "open" {
					return true
				}
			}

			return false
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		fmt.Printf("run finished with warnings: %s\n", *warnings)
		// warnings are fine :3
	}
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %v", err)
	}

	for _, host := range result.Hosts {
		fmt.Printf("Host %s\n", host.Addresses[0])

		for _, port := range host.Ports {
			// RTSP == real time streamimg protocol
			fmt.Printf("\tPort %d open with RTSP service\n", port.ID)
		}
	}

	return result, nil
}

func SlicePortToStr(slicePorts []int) string {

	var sb strings.Builder

	for _, port := range slicePorts {
		sb.WriteString(fmt.Sprintf("%d,", port))
	}

	ports := strings.Trim(sb.String(), ",")
	return ports
}
