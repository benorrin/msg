// Command msgd runs the messaging server.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"msg/internal/server"
	"msg/internal/store"
	"msg/web"
)

func main() {
	var (
		addr     = flag.String("addr", "localhost:8080", "listen address")
		dataDir  = flag.String("data", "./data", "directory for the database and uploaded files")
		maxMB    = flag.Int64("max-file-mb", 25, "maximum upload size in MiB")
		cert     = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
		key      = flag.String("tls-key", "", "TLS key file")
		behindLB = flag.Bool("trust-proxy", false, "trust X-Forwarded-For/-Proto from a reverse proxy")
	)
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "msg.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	srv, err := server.New(server.Config{DataDir: *dataDir, MaxFileBytes: *maxMB << 20, TrustProxy: *behindLB}, st, web.FS)
	if err != nil {
		log.Fatal(err)
	}
	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}()

	log.Printf("listening on %s (data: %s)", *addr, *dataDir)
	if *cert != "" {
		err = hs.ListenAndServeTLS(*cert, *key)
	} else {
		err = hs.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
