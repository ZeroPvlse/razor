package portscan_test

import (
	"testing"

	portscan "github.com/ZeroPvlse/razor/portScan"
)

func TestSlicePortToStr(t *testing.T) {
	got := portscan.SlicePortToStr([]int{10, 20})
	want := "10,20"

	if got != want {
		t.Errorf("%v got but wanted %v\n", got, want)
	}
}
