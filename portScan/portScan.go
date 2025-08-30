package portscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

// formatPorts returns a comma separated list of ports. An empty slice results
// in an empty string which lets nmap decide the default port range.
func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var out []string
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%d", p))
	}
	return strings.Join(out, ",")
}

// newScanner creates an nmap.Scanner configured to mimic `nmap -sC -sV -O`.
// Additional nmap options can be provided which is primarily useful for tests
// to override the nmap binary path.
func newScanner(ctx context.Context, cfg config.Razor, opts ...nmap.Option) (*nmap.Scanner, error) {
	portsStr := formatPorts(cfg.Scope.IncludePorts)

	options := []nmap.Option{
		nmap.WithTargets(cfg.Scope.Targets...),
		nmap.WithPorts(portsStr),
		nmap.WithServiceInfo(),
	}
	if cfg.Scope.AllowIntrusive {
		options = append(options, nmap.WithDefaultScript(), nmap.WithOSDetection())
	}
	options = append(options, opts...)

	return nmap.NewScanner(ctx, options...)
}

// Run executes the port scan using the aggressive options.
func Run(cfg config.Razor) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := newScanner(ctx, cfg)
	if err != nil {
		return err
	}

	result, warnings, err := scanner.Run()
	if warnings != nil && len(*warnings) > 0 {
		return fmt.Errorf("run finished with warnings: %v", *warnings)
	}
	if err != nil {
		return fmt.Errorf("unable to run nmap scan: %w", err)
	}

	_ = result
	return nil
}
