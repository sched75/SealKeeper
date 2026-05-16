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
	"syscall"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/httpserver"
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

	srv := httpserver.New(cfg, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.Run(ctx); err != nil {
		logger.Error("http server exited with error", "err", err)
		return 1
	}
	logger.Info("sealkeeper stopped cleanly")
	return 0
}

func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	direction := "up"
	if len(args) > 0 && args[0] == "down" {
		direction = "down"
		args = args[1:]
	} else if len(args) > 0 && args[0] == "up" {
		args = args[1:]
	}
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := buildLogger(cfg)

	switch direction {
	case "up":
		logger.Info("migrate up — skeleton no-op until migrations/ is wired",
			"database_url", redactDSN(cfg.DatabaseURL))
	case "down":
		logger.Error("migrate down is forbidden in SealKeeper (forward-only, FR-H.61)")
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
