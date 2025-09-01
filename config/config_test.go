package config_test

import (
	"testing"

	"github.com/ZeroPvlse/razor/config"
)

func TestSlicePortToStr(t *testing.T) {
	type tests struct {
		got  string
		want string
	}

	testCases := []tests{
		{
			got:  config.SlicePortToStr([]int{10, 20, 30}),
			want: "10,20,30",
		},
		{
			got:  config.SlicePortToStr([]int{0, 0, 0, 0}),
			want: "0,0,0,0",
		},
		{
			got:  config.SlicePortToStr([]int{-1, 0, 0, 0}),
			want: "-1,0,0,0",
		},
	}

	for _, test := range testCases {

		if test.got != test.want {
			t.Errorf("%v got but wanted %v\n", test.got, test.want)
		}
	}
}
