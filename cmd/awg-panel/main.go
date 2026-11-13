package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"awg-panel/internal/config"
	"awg-panel/internal/httpapi"
	"awg-panel/internal/network"
	"awg-panel/internal/service"
	"awg-panel/internal/store"
)

const socket = "/run/awg-panel/admin.sock"

func main() {
	if err := run(); err != nil {
		slog.Error("Panel stopped", "error", err)
		os.Exit(1)
	}
}
func localRequest(path string, print bool) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	c := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	resp, err := c.Get("http://localhost" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("local check failed: HTTP %d", resp.StatusCode)
	}
	if print {
		_, err = io.Copy(os.Stdout, resp.Body)
	}
	return err
}
func run() error {
	health := flag.Bool("healthcheck", false, "Check the local daemon and firewall")
	bootstrap := flag.Bool("bootstrap", false, "Print the first enabled home configuration and link")
	flag.Parse()
	if *health {
		return localRequest("/health", false)
	}
	if *bootstrap {
		return localRequest("/bootstrap", true)
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	os.Unsetenv("AWG_PASSWORD")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	st, err := store.Open(c.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	state, err := st.Load()
	if err != nil {
		return err
	}
	n, err := network.Detect(ctx, c)
	if err != nil {
		return err
	}
	slog.Info("Network detected", "wan4", n.WAN4, "ipv6", n.IPv6)
	if c.IPv6Mode != "disabled" && !n.IPv6 {
		slog.Info("No routed IPv6 address found; using IPv4-only mode")
	}
	child := exec.Command("amneziawg-go", "-f", network.Interface)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(os.Environ(), "LOG_LEVEL=error")
	if err = child.Start(); err != nil {
		return err
	}
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait(); close(childDone) }()
	defer func() {
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case <-childDone:
		case <-time.After(3 * time.Second):
			_ = child.Process.Kill()
		}
	}()
	defer func() {
		stop, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = n.Down(stop)
	}()
	if err = n.WaitInterface(ctx); err != nil {
		return err
	}
	if err = n.Configure(ctx, state); err != nil {
		return err
	}
	s := &service.Service{State: state, Store: st, Network: n, Config: c, Fatal: make(chan error, 1)}
	api, err := httpapi.New(s)
	if err != nil {
		return err
	}
	defer api.Close()
	c.Password, s.Config.Password, n.Config.Password = "", "", ""
	go s.Watch(ctx)
	defer cancel()
	errorsCh := make(chan error, 8)
	var servers []*http.Server
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()
	listen := func(networkName, address string, handler http.Handler) error {
		listener, e := net.Listen(networkName, address)
		if e != nil {
			return e
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, server)
		go func() {
			if e := server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
				errorsCh <- e
			}
		}()
		return nil
	}
	internal := net.JoinHostPort("10.8.0.1", strconv.Itoa(c.PanelPort))
	wildcard := net.JoinHostPort("0.0.0.0", strconv.Itoa(c.PanelPort))
	if c.ExternalBind != wildcard {
		if err = listen("tcp4", internal, api); err != nil {
			return err
		}
	}
	if c.ExternalBind != "" {
		if err = listen("tcp4", c.ExternalBind, api); err != nil {
			return err
		}
	}
	if n.IPv6 {
		if err = listen("tcp6", net.JoinHostPort("fd42:8::1", strconv.Itoa(c.PanelPort)), api); err != nil {
			return err
		}
	}
	_ = os.Remove(socket)
	local := http.NewServeMux()
	local.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if e := s.Healthy(r.Context()); e != nil {
			http.Error(w, "Service is not healthy", 503)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	local.HandleFunc("GET /bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		for _, p := range s.List() {
			if p.Group == "home" && p.Enabled {
				conf, e := s.Export(p.ID, false)
				if e != nil {
					http.Error(w, "Export failed", 500)
					return
				}
				link, e := s.Export(p.ID, true)
				if e != nil {
					http.Error(w, "Export failed", 500)
					return
				}
				_, _ = fmt.Fprintf(w, "First home device: %s\n\n%s\n%s\n", p.Name, conf, link)
				return
			}
		}
		http.Error(w, "No home device is available", 404)
	})
	if err = listen("unix", socket, local); err != nil {
		return err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	slog.Info("Panel ready", "internal", internal, "external", c.ExternalBind)
	select {
	case <-ctx.Done():
	case err = <-errorsCh:
		return err
	case err = <-s.Fatal:
		return err
	case err = <-childDone:
		if err == nil {
			err = fmt.Errorf("AWG process exited")
		}
		return err
	}
	stop, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	for _, server := range servers {
		_ = server.Shutdown(stop)
	}
	return nil
}
