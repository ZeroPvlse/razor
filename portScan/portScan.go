package portscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

func Run(cfg config.Razor) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ports := SlicePortToStr(cfg.Scope.IncludePorts)

	scanner, err := nmap.NewScanner(
		ctx, nmap.WithTargets(cfg.Scope.Targets...), nmap.WithPorts(ports),
	)
	if err != nil {
		return err
	}

	_, warnings, err := scanner.Run()

	if len(*warnings) > 0 {
		return fmt.Errorf("run finished with warnings: %s\n", err)
	}
	if err != nil {
		return fmt.Errorf("unable to run nmap scan: %s\n", err)
	}

	return nil

}

func SlicePortToStr(slicePorts []int) string {

	var sb strings.Builder

	for _, port := range slicePorts {
		sb.WriteString(fmt.Sprintf("%d,", port))
	}

	ports := strings.Trim(sb.String(), ",")
	return ports
}
