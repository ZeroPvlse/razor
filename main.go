package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ZeroPvlse/razor/defaults"
	"github.com/ZeroPvlse/razor/mess"
	"github.com/akamensky/argparse"
	"gopkg.in/yaml.v3"
)

// for tomorrow
// somehow embed nmap and gobuster (doable)

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

type RazorConfig struct {
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

func LoadConfig(path string) (*RazorConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c RazorConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	applyDefaults(&c)
	if err := validate(c); err != nil {
		return nil, err
	}
	return &c, nil
}

func applyDefaults(c *RazorConfig) {
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

func validate(c RazorConfig) error {
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

func main() {
	parser := argparse.NewParser("print", "Prints provided string to stdout")

	// gen tempate lol
	template := parser.String("t", "template", &argparse.Options{
		Required: false,
		Help:     "Generates YAML template required to operate with value taken from flag",
	})

	// read file
	run := parser.String("r", "run", &argparse.Options{
		Required: false,
		Help:     "",
		Default:  applyDefaults,
	})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	if *template != "" {
		mess.GenerateTemplate(*template)
	}

	razorCfg, err := LoadConfig(*run)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	outDir := razorCfg.Report.OutDir
	if outDir == "" {
		outDir = filepath.Join(".", "artifacts", sanitize(razorCfg.Client), sanitize(razorCfg.Name))
	}
	fmt.Printf("Loaded config for %s (%s)\n", razorCfg.Name, razorCfg.Client)
	fmt.Printf("- Targets: %v\n", razorCfg.Scope.Targets)
	fmt.Printf("- Include ports: %v\n", razorCfg.Scope.IncludePorts)
	if !razorCfg.Scope.TimeWindow.Start.IsZero() {
		fmt.Printf("- Time window (UTC): %s .. %s\n",
			razorCfg.Scope.TimeWindow.Start.UTC().Format(time.RFC3339),
			razorCfg.Scope.TimeWindow.End.UTC().Format(time.RFC3339))
	}
	fmt.Printf("- Limits: %+v\n", razorCfg.Limits)
	fmt.Printf("- Deliverables: %v\n", razorCfg.Report.Deliverables)
	fmt.Printf("- Output dir: %s\n", outDir)

}

func sanitize(s string) string {
	// trivial filesystem-safe-ish
	rs := []rune(s)
	out := make([]rune, 0, len(rs))
	for _, r := range rs {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
