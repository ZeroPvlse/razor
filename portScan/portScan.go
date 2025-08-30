package portscan

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

func Run(cfg config.Razor) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ports := formatPorts(cfg.Scope.IncludePorts)

	scanner, err := nmap.NewScanner(
		ctx, nmap.WithTargets(cfg.Scope.Targets...), nmap.WithPorts(ports),
	)
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

func formatPorts(ports []int) string {
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}
