package portscan

import "testing"

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{80}, "80"},
		{[]int{80, 443, 8080}, "80,443,8080"},
	}
	for _, tt := range tests {
		if got := formatPorts(tt.in); got != tt.want {
			t.Errorf("formatPorts(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
