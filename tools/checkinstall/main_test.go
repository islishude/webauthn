package main

import "testing"

func TestFixedVersionInput(t *testing.T) {
	for _, value := range []string{"v0.1.0", "v0.1.0-rc.1", "v0.0.0-20260926000000-0123456789ab", "0123456789abcdef0123456789abcdef01234567"} {
		if !fixedVersion.MatchString(value) {
			t.Fatalf("rejected fixed revision %q", value)
		}
	}
	for _, value := range []string{"", "main", "latest", "v0", "v0.1", "0123456", "-u", "v1.0.0;echo", "v1.0.0\n", "../local"} {
		if fixedVersion.MatchString(value) {
			t.Fatalf("accepted non-fixed revision %q", value)
		}
	}
}
