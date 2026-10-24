package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

type ControlPlaneStore struct {
	db                 *sql.DB
	secretKey          []byte
	secretFallbackKeys [][]byte
}

func OpenControlPlane(ctx context.Context, path string) (*ControlPlaneStore, error) {
	defer SecureDBFiles(path)
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open control-plane sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		if isMalformedSQLiteError(err) {
			store := &ControlPlaneStore{db: db}
			if initErr := store.initSchema(ctx); initErr != nil {
				db.Close()
				return nil, fmt.Errorf("repair malformed control-plane sqlite database after ping failure: %w", initErr)
			}
			return store, nil
		}
		db.Close()
		return nil, fmt.Errorf("ping control-plane sqlite database: %w", err)
	}

	store := &ControlPlaneStore{db: db}
	if err := store.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *ControlPlaneStore) Close() error {
	return s.db.Close()
}

func (s *ControlPlaneStore) Healthcheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}
