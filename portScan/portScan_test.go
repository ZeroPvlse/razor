package portscan

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/ZeroPvlse/razor/config"
)

// argsFromScanner returns the nmap arguments for the given scanner by using
// reflection to access the unexported field. This avoids the need to execute
// the nmap binary in tests.
func argsFromScanner(s *nmap.Scanner) []string {
	v := reflect.ValueOf(s).Elem().FieldByName("args")
	return *(*[]string)(unsafe.Pointer(v.UnsafeAddr()))
}

func TestNewScannerIncludesDefaultOptions(t *testing.T) {
	cfg := config.Razor{
		Scope: config.Scope{
			Targets:      []string{"127.0.0.1"},
			IncludePorts: []int{80},
		},
	}

	scanner, err := newScanner(context.Background(), cfg, nmap.WithBinaryPath("nmap"))
	if err != nil {
		t.Fatalf("newScanner returned error: %v", err)
	}

	args := argsFromScanner(scanner)
	for _, opt := range []string{"-sC", "-sV", "-O"} {
		found := false
		for _, a := range args {
			if a == opt {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected scanner args to include %q, got %v", opt, args)
		}
	}
}
