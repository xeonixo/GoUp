package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type readyzResponse struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reasons := s.collectReadyReasons(r.Context())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if len(reasons) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(readyzResponse{Status: "unavailable", Reasons: reasons})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(readyzResponse{Status: "ok"})
}

func (s *Server) collectReadyReasons(ctx context.Context) []string {
	if s.readyCheck != nil {
		return s.readyCheck(ctx)
	}
	return s.localReadyReasons(ctx)
}

// localReadyReasons is used when App.Ready is not wired (tests / partial servers).
func (s *Server) localReadyReasons(ctx context.Context) []string {
	reasons := make([]string, 0, 4)

	if s.controlStore != nil {
		if err := s.controlStore.Healthcheck(ctx); err != nil {
			reasons = append(reasons, "control_plane: "+err.Error())
		}
	} else if s.store != nil {
		if err := s.store.Healthcheck(ctx); err != nil {
			reasons = append(reasons, "store: "+err.Error())
		}
	} else {
		reasons = append(reasons, "control_plane: unavailable")
	}

	tenantsChecked := 0
	if s.controlStore != nil && s.tenantStores != nil {
		tenants, err := s.controlStore.GetAllTenants(ctx)
		if err != nil {
			reasons = append(reasons, "tenants: "+err.Error())
		} else {
			for _, tenant := range tenants {
				if !tenant.Active || !tenantDBFileExists(tenant.DBPath) {
					continue
				}
				tenantsChecked++
				tenantStore, storeErr := s.tenantStores.StoreForTenant(ctx, tenant.ID)
				if storeErr != nil {
					reasons = append(reasons, fmt.Sprintf("tenant_store:%s: %v", tenant.Slug, storeErr))
					continue
				}
				if pingErr := tenantStore.Healthcheck(ctx); pingErr != nil {
					reasons = append(reasons, fmt.Sprintf("tenant_store:%s: %v", tenant.Slug, pingErr))
					continue
				}
				if s.runnerFor != nil && s.runnerFor(tenant.ID) == nil {
					reasons = append(reasons, fmt.Sprintf("runner:%s: missing", tenant.Slug))
				}
			}
		}
	}

	if tenantsChecked == 0 && s.store != nil {
		if err := s.store.Healthcheck(ctx); err != nil {
			reasons = append(reasons, "tenant_store:default: "+err.Error())
		}
	}

	return reasons
}

func tenantDBFileExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
