package main

import "testing"

func TestApplicationModeDefaultsAndValidation(t *testing.T) {
	s := defaultSettings(t.TempDir())
	if s.applyMode() != "restart" {
		t.Fatal("legacy/default settings must use controlled restart")
	}
	for _, mode := range []string{"", "restart", "reload"} {
		s.ApplyMode = mode
		if err := s.validate(); err != nil {
			t.Fatalf("valid mode %q: %v", mode, err)
		}
	}
	if s.applyMode() != "reload" {
		t.Fatal("explicit hot reload not respected")
	}
	s.ApplyMode = "arbitrary-command"
	if err := s.validate(); err == nil {
		t.Fatal("unknown application mode accepted")
	}
}
