package httpserver

import "testing"

func TestSanitizeEmailHeader(t *testing.T) {
	cases := map[string]string{
		"plain":                         "plain",
		"with\r\nBcc: evil@example.com": "withBcc: evil@example.com",
		"a\x00b\nc":                     "abc",
	}
	for in, want := range cases {
		if got := sanitizeEmailHeader(in); got != want {
			t.Fatalf("sanitizeEmailHeader(%q) = %q, want %q", in, got, want)
		}
	}
}
