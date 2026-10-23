package auth

import (
	"encoding/json"
	"testing"
)

func TestFlexStrings(t *testing.T) {
	var v struct {
		G flexStrings `json:"g"`
	}
	for in, want := range map[string]int{`{"g":["a","b"]}`: 2, `{"g":"a"}`: 1, `{"g":42}`: 0, `{}`: 0} {
		v.G = nil
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if len(v.G) != want {
			t.Fatalf("%s: got %v", in, v.G)
		}
	}
}

func TestDynamicOIDCCacheIsBounded(t *testing.T) {
	m := NewDynamicOIDCManager(false)
	m.mu.Lock()
	for i := 0; i < maxDynamicOIDCCacheEntries+20; i++ {
		key := "https://issuer-" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
		for len(m.order) >= maxDynamicOIDCCacheEntries {
			m.forgetLocked(m.order[0])
		}
		m.order = append(m.order, key)
		m.providers[key] = nil
	}
	m.mu.Unlock()
	if len(m.providers) > maxDynamicOIDCCacheEntries {
		t.Fatalf("provider cache grew to %d", len(m.providers))
	}
}
