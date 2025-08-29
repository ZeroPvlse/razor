package portscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

func Run(cfg config.Razor) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ports := ""
	for port := range cfg.Scope.IncludePorts {
		ports = string(port) + ","
	}

	ports = strings.Trim(ports, ",")

	scanner, err := nmap.NewScanner(
		ctx, nmap.WithTargets(cfg.Scope.Targets...), nmap.WithPorts(ports),
	)
	if err != nil {
		return err
	}

	result, warnings, err := scanner.Run()

	if len(*warnings) > 0 {
		return errors.New(fmt.Sprintf("run finished with warnings: %s\n", err))
	}
	if err != nil {
		return errors.New(fmt.Sprintf("unable to run nmap scan: %s\n", err))
	}

	return nil

}
