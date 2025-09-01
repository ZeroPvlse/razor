package config_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// ---------------

func TestEnum_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	var rz config.Razor
	rz.Scope.Targets = []string{srv.URL}
	rz.HTTP = srv.Client()

	out, err := rz.Enum(context.Background(), []string{"admin", "login"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) != 1 || out[0].Endpoint != srv.URL+"/admin" || out[0].StatusCode != 200 {
		t.Fatalf("got %#v", out)
	}
}
