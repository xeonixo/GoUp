package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"goup/internal/app"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "backup":
			if err := runBackup(os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		case "rekey-secrets":
			if err := runRekeySecrets(os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer application.Close()

	if err := application.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outputBase := fs.String("o", "", "output base directory (default: $GOUP_DATA_DIR/backups)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlPlaneDBPath), 0o700); err != nil {
		return fmt.Errorf("create control plane dir: %w", err)
	}
	ctx := context.Background()
	controlStore, err := store.OpenControlPlane(ctx, cfg.ControlPlaneDBPath)
	if err != nil {
		return fmt.Errorf("open control plane: %w", err)
	}
	defer controlStore.Close()

	tenants, err := controlStore.GetAllTenants(ctx)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	backupDir, err := store.BackupAll(ctx, cfg.DataDir, cfg.ControlPlaneDBPath, controlStore.DB(), tenants, strings.TrimSpace(*outputBase))
	if err != nil {
		return err
	}
	fmt.Println(backupDir)
	return nil
}

func runRekeySecrets(args []string) error {
	fs := flag.NewFlagSet("rekey-secrets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dryRun := fs.Bool("dry-run", false, "count decryptable secrets without rewriting ciphertext")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlPlaneDBPath), 0o700); err != nil {
		return fmt.Errorf("create control plane dir: %w", err)
	}
	ctx := context.Background()
	controlStore, err := store.OpenControlPlane(ctx, cfg.ControlPlaneDBPath)
	if err != nil {
		return fmt.Errorf("open control plane: %w", err)
	}
	defer controlStore.Close()

	var fallbacks []string
	if previous := strings.TrimSpace(cfg.SSOSecretKeyPrevious); previous != "" {
		fallbacks = append(fallbacks, previous)
	}
	if session := strings.TrimSpace(cfg.SessionKey); session != "" {
		fallbacks = append(fallbacks, session)
	}
	if err := controlStore.ConfigureSecretKeys(cfg.SSOSecretKey, fallbacks...); err != nil {
		return fmt.Errorf("configure secret keys: %w", err)
	}

	if *dryRun {
		count, err := controlStore.CountDecryptableSecrets(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("decryptable secrets: %d\n", count)
		return nil
	}

	updated, err := controlStore.ReencryptAllSecrets(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("re-encrypted secrets: %d\n", updated)
	return nil
}
