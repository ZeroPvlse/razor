package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ZeroPvlse/razor/config"
	"github.com/ZeroPvlse/razor/mess"
	"github.com/akamensky/argparse"
)

// for tomorrow
// somehow embed nmap and gobuster (doable)

func main() {
	parser := argparse.NewParser("print", "Prints provided string to stdout")

	// gen tempate lol
	template := parser.String("g", "gen", &argparse.Options{

		Required: false,
		Help:     "Generates YAML template required to operate with value taken from flag",
	})

	// read file
	run := parser.String("r", "run", &argparse.Options{
		Required: false,
		Help:     "",
		Default:  config.ApplyDefaults,
	})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	if *template != "" {
		mess.GenerateTemplate(*template)
	}

	razorCfg, err := config.Load(*run)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	mess.PrintAscii()

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
