package sqlite

import "testing"

func TestNormalizeTenantRole(t *testing.T) {
	cases := map[string]string{
		"admin":    "admin",
		"Admin":    "admin",
		"operator": "operator",
		"OPERATOR": "operator",
		"viewer":   "viewer",
		"":         "viewer",
		"other":    "viewer",
	}
	for in, want := range cases {
		if got := NormalizeTenantRole(in); got != want {
			t.Fatalf("NormalizeTenantRole(%q)=%q want %q", in, got, want)
		}
	}
	if !TenantRoleCanWrite("admin") || !TenantRoleCanWrite("operator") || TenantRoleCanWrite("viewer") {
		t.Fatal("TenantRoleCanWrite mismatch")
	}
}
