// Command pisentry-panel is the fleet panel for pisentry agents. Agents push
// events to it; it never connects to them. See docs/adr/0002-fleet-panel.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/pisentry/pisentry/panel/internal/server"
	"github.com/pisentry/pisentry/panel/internal/store"
	"github.com/pisentry/pisentry/panel/internal/web"
)

var version = "dev"

const usage = `pisentry-panel: the fleet panel for pisentry agents

  pisentry-panel serve        [-listen 127.0.0.1:8443] [-data DIR] [-tls-cert FILE -tls-key FILE]
                              [-quiet-after 3m] [-retention 720h]
  pisentry-panel host add     [-data DIR] [-url URL] NAME   register a Pi and print its install command
  pisentry-panel host list    [-data DIR]
  pisentry-panel host rm      [-data DIR] NAME              revoke its token and delete its events
  pisentry-panel admin-token  [-data DIR]                   the token the web UI asks for
  pisentry-panel version
`

const defaultData = "/var/lib/pisentry-panel"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "host":
		err = cmdHost(os.Args[2:])
	case "admin-token":
		err = cmdAdminToken(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pisentry-panel:", err)
		os.Exit(1)
	}
}

func openStore(dir string) (*store.Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, "panel.db"))
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8443", "address to listen on")
	data := fs.String("data", defaultData, "data directory")
	cert := fs.String("tls-cert", "", "TLS certificate (PEM)")
	key := fs.String("tls-key", "", "TLS private key (PEM)")
	quiet := fs.Duration("quiet-after", 3*time.Minute, "mark a host quiet after this long with nothing from it")
	keep := fs.Duration("retention", 30*24*time.Hour, "keep events this long")
	fs.Parse(args)

	if (*cert == "") != (*key == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	if err := server.CheckListen(*listen, *cert != ""); err != nil {
		return err
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	s := &server.Server{Store: st, QuietAfter: *quiet, UI: web.Handler(), Log: log}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.Prune(ctx, *keep)

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", *listen, "tls", *cert != "", "ui", web.Built(), "version", version)
		if *cert != "" {
			errc <- srv.ListenAndServeTLS(*cert, *key)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func cmdHost(args []string) error {
	if len(args) == 0 {
		return errors.New("host: add, list or rm")
	}
	fs := flag.NewFlagSet("host "+args[0], flag.ExitOnError)
	data := fs.String("data", defaultData, "data directory")
	url := fs.String("url", "https://PANEL:8443", "panel URL the Pi will push to")
	fs.Parse(args[1:])
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	switch args[0] {
	case "add":
		if fs.NArg() != 1 {
			return errors.New("host add: give one NAME")
		}
		tok, err := st.AddHost(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Printf("Added %s. Its token is shown only now:\n\n  %s\n\n", fs.Arg(0), tok)
		fmt.Printf("Run this on the Pi (needs the agent's panel output, #76):\n\n")
		fmt.Printf("  curl -fsSL https://raw.githubusercontent.com/pisentry/pisentry/main/deploy/install.sh | sudo bash -s -- --panel-url %s --panel-token %s\n", *url, tok)
		return nil
	case "list":
		hs, err := st.Hosts(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tLAST SEEN\tREPORTS AS")
		for _, h := range hs {
			seen := "never"
			if !h.LastSeen.IsZero() {
				seen = h.LastSeen.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", h.Name, seen, h.ReportedAs)
		}
		return tw.Flush()
	case "rm":
		if fs.NArg() != 1 {
			return errors.New("host rm: give one NAME")
		}
		if err := st.DeleteHost(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Printf("Removed %s, its token and its events.\n", fs.Arg(0))
		return nil
	}
	return fmt.Errorf("host %q: use add, list or rm", args[0])
}

func cmdAdminToken(args []string) error {
	fs := flag.NewFlagSet("admin-token", flag.ExitOnError)
	data := fs.String("data", defaultData, "data directory")
	fs.Parse(args)
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	tok, err := st.AdminToken(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
