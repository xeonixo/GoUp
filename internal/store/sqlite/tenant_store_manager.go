package sqlite

import (
	"context"
	"fmt"
	"sync"
)

type TenantStoreManager struct {
	control         *ControlPlaneStore
	defaultTenantID int64
	defaultStore    *Store
	mu              sync.Mutex
	stores          map[int64]*Store
}

func NewTenantStoreManager(control *ControlPlaneStore, defaultTenant Tenant, defaultStore *Store) *TenantStoreManager {
	return &TenantStoreManager{
		control:         control,
		defaultTenantID: defaultTenant.ID,
		defaultStore:    defaultStore,
		stores:          make(map[int64]*Store),
	}
}

func (m *TenantStoreManager) StoreForTenant(ctx context.Context, tenantID int64) (*Store, error) {
	if tenantID <= 0 || tenantID == m.defaultTenantID {
		return m.defaultStore, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if store, ok := m.stores[tenantID]; ok {
		return store, nil
	}

	tenant, err := m.control.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !tenant.Active {
		return nil, fmt.Errorf("tenant %q is inactive", tenant.Slug)
	}

	store, err := Open(ctx, tenant.DBPath)
	if err != nil {
		return nil, err
	}
	m.stores[tenantID] = store
	return store, nil
}

func (m *TenantStoreManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for tenantID, store := range m.stores {
		if err := store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.stores, tenantID)
	}
	return firstErr
}
