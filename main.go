package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/akamensky/argparse"
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
		generateTemplate(*template)
	}

	rzrCfg, err := LoadConfig(*run)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	outDir := rzrCfg.Report.OutDir
	if outDir == "" {
		outDir = filepath.Join(".", "artifacts", sanitize(rzrCfg.Client), sanitize(rzrCfg.Name))
	}
	fmt.Printf("Loaded config for %s (%s)\n", rzrCfg.Name, rzrCfg.Client)
	fmt.Printf("- Targets: %v\n", rzrCfg.Scope.Targets)
	fmt.Printf("- Include ports: %v\n", rzrCfg.Scope.IncludePorts)
	if !rzrCfg.Scope.TimeWindow.Start.IsZero() {
		fmt.Printf("- Time window (UTC): %s .. %s\n",
			rzrCfg.Scope.TimeWindow.Start.UTC().Format(time.RFC3339),
			rzrCfg.Scope.TimeWindow.End.UTC().Format(time.RFC3339))
	}
	fmt.Printf("- Limits: %+v\n", rzrCfg.Limits)
	fmt.Printf("- Deliverables: %v\n", rzrCfg.Report.Deliverables)
	fmt.Printf("- Output dir: %s\n", outDir)

}

func generateTemplate(filename string) error {
	if strings.Contains(filename, ".") {
		return errors.New("template file name have contain '.'")
	}

	fileSuff := fmt.Sprintf("%s.yaml", filename)

	file, err := os.Create(fileSuff)
	if err != nil {
		fmt.Print(err.Error())
	}
	defer file.Close()

	fmt.Printf("Generated: %s successfuly!\n", fileSuff)
	file.WriteString(`# RAZOR engagement config FILL THIS B4 YOU GO!!
name: ""                            # what are we calling this job? keep it short. shows up in reports/artifacts.
client: ""                          # who hired us. spell it right so we don't look like amateurs.

scope:
  targets: []                       # EXACT stuff we're allowed to poke: domains/IPs/CIDRs. if it’s not here, we don’t touch it.
  include_ports: []                 # only list ports if the client is picky. blank = safe defaults; we won't scan half the internet.
  max_hosts: 0                      # seatbelt for huge scopes. 0 = no cap. turn it up if time is tight and scope is thicc. it basically means from whole scope how many findings are the "key ones". it will automatically pick the most crucial ones UP TO max_hosts value.
  allow_intrusive: false            # leave false unless client said "go harder." true = spicier checks, more noise, more sideeye. (XSSscannig, sqli shit like that)
  time_window:                      # optional 'do it off-hours' window (UTC). leave blank if nobody cares.
    start: ""                       # e.g. "2025-09-01T19:00:00Z" - or empty if no window.
    end: ""                         # e.g. "2025-09-02T06:00:00Z" - or empty, same deal.

limits:
  rps_per_host: 2                   # requests/sec per host. chill setting so WAFs don't start drama.
  total_requests_per_host: 1000     # hard stop so a typo doesn't firehose a site. we’re scanners, not DDoSers.
  concurrency: 10                   # how many things we juggle at once. higher = faster & louder. lower = slower & stealthier.
  connect_timeout_s: 5              # if we can't connect by now, we move on. life's short.
  request_timeout_s: 10             # don't wait forever for sleepy servers.
  retries: 2                        # how many second chances we give flaky endpoints before we say "nah."

report:
  deliverables: []                  # what to spit out. pick from: pdf_exec, html_tech, json_findings. blank = reasonable defaults.
  redactions: true                  # keep secrets blurred in evidence/logs. leave true unless you enjoy awkward calls.
  cvss: "v3.1"                      # severity flavor. you probably don't need to touch this.
  include_screenshots: true         # screenshots = receipts. turn off only if storage is crying.
  out_dir: ""                       # where to dump files. blank = default folder; we keep it tidy.

notes:
  stack_hints: []                   # client hints like "WordPress", "Nginx", "AWS". guesses welcome; helps aim checks.
  contacts: []                      # who we ping if something looks spicy. emails or chat handles. no ghosting.
  tags: []                          # labels for later: "prod", "EU", "quarterly", "pls-don't-break".`)

	return nil
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
