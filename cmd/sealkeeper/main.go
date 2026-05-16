// Command sealkeeper is the entry point of the SealKeeper distribution.
//
// Sub-commands (D-D.x):
//
//	serve     — run the HTTP server (default)
//	migrate   — apply database migrations (forward-only, FR-H.61)
//	backup    — create or restore backup tarballs (FR-H.53/54)
//	version   — print build metadata
//
// Configuration precedence is documented in internal/config.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"crypto/rand"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/httpserver"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/tokens"
	"github.com/sched75/sealkeeper/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "serve")
	}

	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "migrate":
		os.Exit(runMigrate(os.Args[2:]))
	case "backup":
		os.Exit(runBackup(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("sealkeeper", version.String(), "/", version.GoVersion())
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `sealkeeper %s

Usage:
  sealkeeper <command> [flags]

Commands:
  serve      Run the HTTP server (default if no command given)
  migrate    Apply database migrations (forward-only)
  backup     Create or restore a backup
  version    Print build metadata
  help       Show this message

Run "sealkeeper <command> -h" for command-specific flags.
`, version.String())
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "override SK_HTTP_LISTEN (e.g. :8443)")
	configFile := fs.String("config", "", "override SK_CONFIG_FILE path")
	_ = fs.Parse(args)

	if *configFile != "" {
		_ = os.Setenv("SK_CONFIG_FILE", *configFile)
	}
	if *listen != "" {
		_ = os.Setenv("SK_HTTP_LISTEN", *listen)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}

	logger := buildLogger(cfg)
	logger.Info("sealkeeper starting",
		"version", version.Version,
		"commit", version.Commit,
		"mode", string(cfg.Mode),
	)

	if cfg.IsEval() {
		// FR-H.11..19 — surface the eval-mode warnings prominently.
		logger.Warn("running in evaluation mode — not for production")
		if cfg.MasterSecret != "" {
			logger.Warn("eval: master secret auto-generated; persist it for repeatable runs")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := storage.Open(ctx, storage.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		logger.Error("storage open failed", "err", err, "dsn", redactDSN(cfg.DatabaseURL))
		return 1
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			logger.Warn("storage close failed", "err", cerr)
		}
	}()

	if cfg.IsEval() {
		// Eval mode runs migrations automatically so `docker run … -e SK_MODE=eval`
		// works with zero ceremony (FR-H.11..19). Production deployments are
		// expected to run `sealkeeper migrate up` as a discrete step (FR-H.63).
		if err := store.MigrateUp(ctx); err != nil {
			logger.Error("eval auto-migrate failed", "err", err)
			return 1
		}
	}

	srv := httpserver.New(cfg, logger)
	srv.Readiness().Add(storage.NewReadinessCheck("database", store))
	srv.SetTokens(tokens.NewRepo(store.DB()))
	srv.SetAudit(audit.NewRepo(store.DB()))
	if sender, err := buildSender(cfg, logger); err != nil {
		logger.Error("mailer setup failed", "err", err)
		return 1
	} else if sender != nil {
		srv.SetSender(sender)
	}

	// Admin console — TOTP + sessions need the master-key-derived cipher.
	box, err := cryptobox.New(cfg.MasterSecret)
	if err != nil {
		logger.Error("cryptobox init failed", "err", err)
		return 1
	}
	adminRepo := admin.NewRepo(store.DB(), box)
	if err := bootstrapAdminIfNeeded(ctx, adminRepo, logger); err != nil {
		logger.Error("admin bootstrap failed", "err", err)
		return 1
	}
	srv.SetAdmin(adminRepo, cfg.InstanceDomain)
	domainsRepo := domains.NewRepo(store.DB())
	elevationsRepo := elevations.NewRepo(store.DB())
	policiesRepo := policies.NewRepo(store.DB(), domainsRepo, elevationsRepo)
	srv.SetDomains(domainsRepo)
	srv.SetPolicies(policiesRepo, elevationsRepo)

	librariesRepo, err := libraries.NewRepo(store.DB(), cfg.LibrariesDir)
	if err != nil {
		logger.Error("libraries init failed", "err", err)
		return 1
	}
	srv.SetLibraries(librariesRepo)

	if err := srv.Run(ctx); err != nil {
		logger.Error("http server exited with error", "err", err)
		return 1
	}
	logger.Info("sealkeeper stopped cleanly")
	return 0
}

func runMigrate(args []string) int {
	sub := "up"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := buildLogger(cfg)

	if cfg.DatabaseURL == "" {
		fmt.Fprintln(os.Stderr, "migrate: SK_DATABASE_URL is empty")
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := storage.Open(ctx, storage.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage open failed: %v\n", err)
		return 1
	}
	defer store.Close()

	switch sub {
	case "up":
		if err := store.MigrateUp(ctx); err != nil {
			logger.Error("migrate up failed", "err", err)
			return 1
		}
		v, _ := store.SchemaVersion(ctx)
		logger.Info("migrate up complete",
			"dialect", string(store.Dialect()),
			"schema_version", v,
			"database_url", redactDSN(cfg.DatabaseURL),
		)
	case "status":
		v, err := store.SchemaVersion(ctx)
		if err != nil {
			logger.Error("migrate status failed", "err", err)
			return 1
		}
		fmt.Printf("schema_version=%d dialect=%s\n", v, store.Dialect())
	case "down":
		fmt.Fprintln(os.Stderr, "migrate down is forbidden in SealKeeper (forward-only, FR-H.61)")
		fmt.Fprintln(os.Stderr, "to roll back: restore a backup taken before the failing upgrade")
		return 2
	default:
		fmt.Fprintf(os.Stderr, "unknown migrate sub-command %q (want: up | status)\n", sub)
		return 2
	}
	return 0
}

func runBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "backup requires a sub-command: create | restore")
		return 2
	}
	sub := args[0]
	args = args[1:]

	output := fs.String("output", "", "output path for create")
	input := fs.String("input", "", "input path for restore")
	yes := fs.Bool("yes", false, "confirm destructive restore")
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := buildLogger(cfg)

	switch sub {
	case "create":
		if *output == "" {
			fmt.Fprintln(os.Stderr, "backup create --output <path> required")
			return 2
		}
		logger.Info("backup create — skeleton stub", "output", *output)
	case "restore":
		if *input == "" {
			fmt.Fprintln(os.Stderr, "backup restore --input <path> required")
			return 2
		}
		if !*yes {
			fmt.Fprintln(os.Stderr, "backup restore is destructive; re-run with --yes")
			return 2
		}
		logger.Info("backup restore — skeleton stub", "input", *input)
	default:
		fmt.Fprintf(os.Stderr, "unknown backup sub-command %q\n", sub)
		return 2
	}
	return 0
}

// buildSender chooses the mailer Sender from configuration.
//
// Precedence:
//  1. SK_SMTP_HOST set → SMTPSender, regardless of mode (handy for staging
//     under eval mode against a captured-only relay like Mailpit).
//  2. Eval mode without SMTP_HOST → leave the server's default
//     CaptureSender in place (returns nil here).
//  3. Production without SMTP_HOST → log a startup warning and keep the
//     NopSender that the server defaults to. Operators usually want to
//     spot this fast; the warning is loud.
func buildSender(cfg config.Config, logger *slog.Logger) (mailer.Sender, error) {
	if strings.TrimSpace(cfg.SMTPHost) == "" {
		if !cfg.IsEval() {
			logger.Warn("no SMTP relay configured — reveal mails will be silently dropped (set SK_SMTP_HOST or run in eval mode)")
		}
		return nil, nil
	}
	tlsMode := mailer.TLSAuto
	if cfg.SMTPTLS != "" {
		tlsMode = mailer.TLSMode(cfg.SMTPTLS)
	}
	smtpCfg := mailer.SMTPConfig{
		Host:               cfg.SMTPHost,
		Port:               cfg.SMTPPort,
		Username:           cfg.SMTPUsername,
		Password:           cfg.SMTPPassword,
		FromAddress:        cfg.SMTPFrom,
		TLS:                tlsMode,
		Timeout:            cfg.SMTPTimeout,
		InsecureSkipVerify: cfg.SMTPInsecureTLS,
		ServerName:         cfg.SMTPServerName,
	}
	return mailer.NewSMTPSender(smtpCfg)
}

// bootstrapAdminIfNeeded seeds admin@localhost with a fresh 20-character
// password printed at INFO level (FR-C.1/2) when the admins table is empty.
// The account ships with force_password_change + force_totp_enroll set so
// the operator can't access the console without changing both.
func bootstrapAdminIfNeeded(ctx context.Context, repo *admin.Repo, logger *slog.Logger) error {
	n, err := repo.Count(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pwd, err := randomPassword(20)
	if err != nil {
		return err
	}
	const email = "admin@localhost"
	if _, err := repo.Create(ctx, email, pwd); err != nil {
		return err
	}
	logger.Info("================================================================")
	logger.Info("BOOTSTRAP ADMIN PASSWORD — record this NOW, it will not be reprinted",
		"email", email,
		"password", pwd,
	)
	logger.Info("Sign in at /admin/login to change the password and enrol TOTP.")
	logger.Info("================================================================")
	return nil
}

func randomPassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*+=?"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, x := range b {
		b[i] = alphabet[int(x)%len(alphabet)]
	}
	return string(b), nil
}

func buildLogger(cfg config.Config) *slog.Logger {
	var lvl slog.Level
	switch cfg.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// redactDSN strips the password from a libpq-style URL for log output.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	// crude redaction good enough for log lines; keeps scheme and host visible.
	if at := indexOfRune(dsn, '@'); at > 0 {
		if scheme := indexOf(dsn, "://"); scheme > 0 {
			return dsn[:scheme+3] + "***" + dsn[at:]
		}
	}
	return dsn
}

func indexOfRune(s string, r rune) int {
	for i, c := range s {
		if c == r {
			return i
		}
	}
	return -1
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
