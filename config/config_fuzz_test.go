package config

import (
	"bytes"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte("[aurora]\nversion = 2.0\nprofile = balanced\nroute = auto\nspeed = normal\n"),
		[]byte("[local]\nmode = proxy\ndns = system\n"),
		[]byte("[x-client]\nopaque = value\n"),
		[]byte("[aurora\nversion = \""),
		{0x00, 0xff, '\n', '[', ']'},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := Parse(bytes.NewReader(input))
		if err != nil {
			return
		}
		if err := parsed.Validate(); err != nil {
			t.Fatalf("Parse accepted an invalid configuration: %v", err)
		}
	})
}
