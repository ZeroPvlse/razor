package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ZeroPvlse/razor/config"
	"github.com/ZeroPvlse/razor/defaults"
	"github.com/ZeroPvlse/razor/mess"
)

func init() {
	if len(os.Args) > 2 {
		fmt.Println("too many agrs: usage razor [filename].yaml")
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		fmt.Println("too little arguments: usage razor-gen [filename].yaml")
		os.Exit(2)
	}
}

func main() {
	razorCfg, err := config.Load(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(3)
	}

	mess.PrintAscii(mess.MainLogo)

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

	// network scan
	nmapRes, err := razorCfg.Nmap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %v", err)
		os.Exit(4)
	}
	fmt.Println(nmapRes)

	// light web enum
	webEnumRes, err := razorCfg.Enum(context.Background(), defaults.CommonEndpoints)
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %v", err)
		os.Exit(5)
	}
	fmt.Println(webEnumRes)

	// intrusive web vulns (XSS/SQLi) — only if allowed
	if razorCfg.Scope.AllowIntrusive {
		if err := ensureTools("xsstrike", "sqlmap"); err != nil {
			fmt.Fprintf(os.Stderr, "tooling error: %v\n", err)
			os.Exit(6)
		}
		razorCfg.XssScan()
		razorCfg.SQLiScan()
	}
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

func ensureTools(binaries ...string) error {
	for _, b := range binaries {
		if _, err := exec.LookPath(b); err != nil {
			return fmt.Errorf("%s not installed or not in $PATH", b)
		}
	}
	return nil
}
