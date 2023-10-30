package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/justinsb/packages/alpha/postgres/pkg/certs"
	"github.com/justinsb/packages/kinspire/client"

	pgx "github.com/jackc/pgx/v5"
	"k8s.io/klog/v2"
)

func main() {
	err := run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// klog.InitFlags(nil)
	// flag.Parse()

	if err := client.SPIFFE.Init(ctx); err != nil {
		return err
	}

	pgdata := "/volumes/data/pgdata"
	// pgdata := os.Getenv("PGDATA")
	if pgdata == "" {
		return fmt.Errorf("PGDATA not set")
	}

	pgUID := 1000
	pgGID := 1000
	pgEnv := []string{
		"PGDATA=" + pgdata,
		"PATH=" + os.Getenv("PATH"),
	}

	if err := mkdirAll(pgdata, 0750); err != nil {
		return err
	}
	if err := os.Chown(pgdata, pgUID, pgGID); err != nil {
		return fmt.Errorf("error doing Chown(%q, %d, %d): %w", pgdata, pgUID, pgGID, err)
	}

	// TODO: HACK HACK HACK
	os.Remove(filepath.Join(pgdata, "postmaster.pid"))

	if err := mkdirAll("/config", 0750); err != nil {
		return err
	}

	postgres := &Postgres{}
	if err := postgres.writeHBAConf(ctx); err != nil {
		return err
	}
	if err := postgres.writePgIdentConf(ctx); err != nil {
		return err
	}
	if err := postgres.writePostgresConf(ctx); err != nil {
		return err
	}

	alreadyInitialized := true
	b, err := os.ReadFile(filepath.Join(pgdata, "PG_VERSION"))
	if err != nil {
		if os.IsNotExist(err) {
			alreadyInitialized = false
		} else {
			return fmt.Errorf("reading PG_VERSION: %w", err)
		}
	} else {
		klog.Infof("PG_VERSION is %q", string(b))
	}

	if !alreadyInitialized {
		args := []string{
			"--username=postgres",
		}
		cmd := exec.CommandContext(ctx, "initdb", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = pgEnv
		klog.Infof("initializing postgres datadir: %v", strings.Join(cmd.Args, " "))
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	if err := createServerCertificates(ctx, client.SPIFFE.Source()); err != nil {
		return err
	}

	var pg *exec.Cmd
	{
		args := []string{"-c", "config_file=/config/postgres.conf"}

		cmd := exec.CommandContext(ctx, "postgres", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = pgEnv
		klog.Infof("starting postgres: %v", strings.Join(cmd.Args, " "))
		if err := cmd.Start(); err != nil {
			return err
		}
		pg = cmd
	}

	defer func() {
		if pg != nil {
			// TODO: Send SIGTERM and wait a few seconds, then escalate to SIGINT (and then escalate to SIGQUIT)?
			klog.Infof("sending postgres interrupt signal")
			if err := pg.Process.Signal(os.Interrupt); err != nil {
				klog.Warningf("error sending interrupt signal: %v", err)
			}
			if err := pg.Wait(); err != nil {
				klog.Warningf("error waiting for process exit: %v", err)
			} else {
				klog.Infof("postgres exited cleanly")
			}
		}
	}()

	// TODO: Replace with waiting for pg to become ready
	time.Sleep(5 * time.Second)

	{
		db := "gitea"
		owner := "gitea"
		if err := postgres.createRole(ctx, owner); err != nil {
			return err
		}
		if err := postgres.createDB(ctx, db); err != nil {
			return err
		}
		if err := postgres.addOwner(ctx, db, owner); err != nil {
			return err
		}
	}

	if err := pg.Wait(); err != nil {
		return fmt.Errorf("postgres exited: %w", err)
	}
	return nil
}

func mkdirAll(dir string, fileMode os.FileMode) error {
	klog.Infof("setting dir %q to mode %v", dir, fileMode)
	if err := os.MkdirAll(dir, fileMode); err != nil {
		return fmt.Errorf("error doing MkdirAll(%q, %d): %w", dir, fileMode, err)
	}
	if err := os.Chmod(dir, fileMode); err != nil {
		return fmt.Errorf("error doing Chmod(%q, %d): %w", dir, fileMode, err)
	}
	return nil
}

func createServerCertificates(ctx context.Context, source *client.SPIFFESource) error {
	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("getting x509 svid: %w", err)
	}
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("getting x509 trust bundle: %w", err)
	}

	secretsDir := "/secrets/service/"

	if err := mkdirAll(secretsDir, 0700); err != nil {
		return err
	}

	if err := certs.WriteCertificates(filepath.Join(secretsDir, "ca.crt"), bundle.X509Authorities()); err != nil {
		return err
	}

	if err := certs.WriteCertificates(filepath.Join(secretsDir, "server.crt"), svid.Certificates); err != nil {
		return err
	}
	if err := certs.WritePrivateKey(filepath.Join(secretsDir, "server.key"), svid.PrivateKey); err != nil {
		return err
	}

	return nil
}

type Postgres struct {
}

func (c *Postgres) writePostgresConf(ctx context.Context) error {
	config := `
# Listen for TCP
listen_addresses = '*'

# Enable TLS
ssl = on
ssl_ca_file = '/secrets/service/ca.crt'
ssl_cert_file = '/secrets/service/server.crt'
ssl_key_file = '/secrets/service/server.key'

# Other config files
hba_file = '/config/pg_hba.conf'
ident_file = '/config/pg_ident.conf'

log_error_verbosity=VERBOSE
`
	p := "/config/postgres.conf"
	if err := os.WriteFile(p, []byte(config), 0644); err != nil {
		return fmt.Errorf("error writing file %q: %w", p, err)
	}
	return nil
}

func (c *Postgres) writeHBAConf(ctx context.Context) error {
	config := `
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
hostssl all             all             all                     cert clientcert=verify-full map=mapcerts
`
	p := "/config/pg_hba.conf"
	if err := os.WriteFile(p, []byte(config), 0644); err != nil {
		return fmt.Errorf("error writing file %q: %w", p, err)
	}
	return nil
}

func (c *Postgres) writePgIdentConf(ctx context.Context) error {
	// Only one regex is allowed here
	config := `
mapcerts   /^spiffe://k8s\.local/ns/gitea/sa/(.*)$      \1
`
	p := "/config/pg_ident.conf"
	if err := os.WriteFile(p, []byte(config), 0644); err != nil {
		return fmt.Errorf("error writing file %q: %w", p, err)
	}
	return nil
}

func (c *Postgres) createRole(ctx context.Context, roleName string) error {
	url := fmt.Sprintf("postgres:///%s?host=/var/run/postgresql", "postgres")
	klog.Infof("connecting to db %q", url)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer conn.Close(context.Background())

	{
		sql := "SELECT * FROM pg_catalog.pg_roles WHERE rolname=$1"
		args := []any{roleName}
		klog.Infof("running sql %q args=%v", sql, args)
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
		defer rows.Close()
		rowCount := 0
		for rows.Next() {
			rowCount++
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("quering sql %q args=%v: %w", sql, args, err)
		}
		if rowCount != 0 {
			klog.Infof("role %q already exists", roleName)
			return nil
		}
	}

	{
		sql := fmt.Sprintf("CREATE USER %s", pgx.Identifier([]string{roleName}).Sanitize())
		args := []any{}
		klog.Infof("running sql %q args=%v", sql, args)
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
	}
	return nil
}

func (c *Postgres) createDB(ctx context.Context, dbName string) error {
	url := fmt.Sprintf("postgres:///%s?host=/var/run/postgresql", "postgres")
	klog.Infof("connecting to db %q", url)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer conn.Close(context.Background())

	{
		sql := "SELECT * FROM pg_catalog.pg_database WHERE datname=$1"
		args := []any{dbName}
		klog.Infof("running sql %q args=%v", sql, args)
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
		defer rows.Close()
		rowCount := 0
		for rows.Next() {
			rowCount++
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("quering sql %q args=%v: %w", sql, args, err)
		}
		if rowCount != 0 {
			klog.Infof("database %q already exists", dbName)
			return nil
		}
	}

	{
		sql := "CREATE DATABASE " + pgx.Identifier([]string{dbName}).Sanitize()
		args := []any{}
		klog.Infof("running sql %q args=%v", sql, args)
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
	}

	return nil
}

func (c *Postgres) addOwner(ctx context.Context, dbName string, ownerName string) error {
	url := fmt.Sprintf("postgres:///%s?host=/var/run/postgresql", "postgres")
	klog.Infof("connecting to db %q", url)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer conn.Close(context.Background())

	{
		sql := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s", pgx.Identifier([]string{dbName}).Sanitize(), pgx.Identifier([]string{ownerName}).Sanitize())
		args := []any{}
		klog.Infof("running sql %q args=%v", sql, args)
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
	}

	url2 := fmt.Sprintf("postgres:///%s?host=/var/run/postgresql", dbName)
	klog.Infof("connecting to db %q", url2)
	conn2, err := pgx.Connect(ctx, url2)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer conn2.Close(context.Background())
	{
		sql := fmt.Sprintf("GRANT ALL ON SCHEMA public TO %s", pgx.Identifier([]string{ownerName}).Sanitize())
		args := []any{}
		klog.Infof("running sql %q args=%v", sql, args)
		if _, err := conn2.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("running sql %q args=%v: %w", sql, args, err)
		}
	}

	return nil
}
