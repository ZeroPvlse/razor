package portscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

// newScanner creates an nmap.Scanner configured to mimic `nmap -sC -sV -O`.
// Additional nmap options can be provided which is primarily useful for tests
// to override the nmap binary path.
func newScanner(ctx context.Context, cfg config.Razor, opts ...nmap.Option) (*nmap.Scanner, error) {
	var ports []string
	for _, port := range cfg.Scope.IncludePorts {
		ports = append(ports, fmt.Sprintf("%d", port))
	}
	portsStr := strings.Join(ports, ",")

	options := []nmap.Option{
		nmap.WithTargets(cfg.Scope.Targets...),
		nmap.WithPorts(portsStr),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithOSDetection(),
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
