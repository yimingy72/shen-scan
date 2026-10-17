package main

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"scanplatform/internal/cloud"
	"scanplatform/internal/control"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	databaseURL := os.Getenv("DATABASE_URL")
	server, err := control.New(ctx, databaseURL, os.Getenv("SCAN_ADMIN_TOKEN"), os.Getenv("SCAN_JOIN_TOKEN"))
	if err != nil {
		slog.Error("initialize control plane", "error", err)
		os.Exit(1)
	}
	defer server.Close()
	closeCloud, err := cloud.Start(ctx, databaseURL, server)
	if err != nil {
		slog.Error("initialize cloud controller", "error", err)
		os.Exit(1)
	}
	defer closeCloud()

	mux := http.NewServeMux()
	mux.Handle("/api/", server.Handler())
	downloadDirectory := os.Getenv("SCAN_DOWNLOAD_DIR")
	if downloadDirectory == "" {
		mux.HandleFunc("/downloads/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	} else {
		mux.Handle("/downloads/", downloadHandler(downloadDirectory))
	}
	staticDirectory := os.Getenv("SCAN_STATIC_DIR")
	if staticDirectory == "" {
		staticDirectory = "web/dist"
	}
	mux.Handle("/", spaHandler(staticDirectory))
	address := os.Getenv("SCAN_LISTEN_ADDR")
	if address == "" {
		address = ":8080"
	}
	certFile, keyFile := os.Getenv("SCAN_TLS_CERT"), os.Getenv("SCAN_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		slog.Error("SCAN_TLS_CERT and SCAN_TLS_KEY must be set together")
		os.Exit(1)
	}
	httpServer := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		slog.Info("control plane listening", "address", address, "tls", certFile != "")
		var err error
		if certFile != "" {
			err = httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve control plane", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown control plane", "error", err)
	}
}

func spaHandler(directory string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := safeRelative(r.URL.Path, "/")
		if ok && name != "" && serveFile(w, r, directory, name, false) {
			return
		}
		if !serveFile(w, r, directory, "index.html", false) {
			writeMissingUI(w)
		}
	})
}

func downloadHandler(directory string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name, ok := safeRelative(r.URL.Path, "/downloads/")
		if !ok || name == "" || !serveFile(w, r, directory, name, true) {
			http.NotFound(w, r)
		}
	})
}

func safeRelative(requestPath, prefix string) (string, bool) {
	relative := strings.TrimPrefix(requestPath, prefix)
	if relative == requestPath || strings.Contains(relative, `\`) || strings.HasSuffix(relative, "/") {
		return "", false
	}
	clean := strings.TrimPrefix(path.Clean("/"+relative), "/")
	if clean != relative {
		return "", false
	}
	for _, char := range clean {
		if char < 0x20 || char == 0x7f {
			return "", false
		}
	}
	for _, part := range strings.Split(clean, "/") {
		if part == "" || strings.HasPrefix(part, ".") {
			return "", false
		}
	}
	return clean, true
}

func serveFile(w http.ResponseWriter, r *http.Request, directory, name string, download bool) bool {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return false
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if !download && strings.HasPrefix(name, "assets/") {
		// Vite content hashes change the URL whenever the asset changes.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Add("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header.Get("Accept-Encoding")) {
			if compressed, err := root.Open(name + ".gz"); err == nil {
				defer compressed.Close()
				if compressedInfo, err := compressed.Stat(); err == nil && compressedInfo.Mode().IsRegular() {
					file, info = compressed, compressedInfo
					w.Header().Set("Content-Encoding", "gzip")
				}
			}
		}
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if download {
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(name)}))
	}
	http.ServeContent(w, r, path.Base(name), info.ModTime(), file)
	return true
}

func acceptsGzip(header string) bool {
	wildcard := false
	for _, entry := range strings.Split(header, ",") {
		parts := strings.Split(entry, ";")
		encoding := strings.ToLower(strings.TrimSpace(parts[0]))
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, value, _ := strings.Cut(strings.TrimSpace(parameter), "=")
			if strings.EqualFold(key, "q") {
				quality, _ = strconv.ParseFloat(value, 64)
			}
		}
		accepted := quality > 0 && quality <= 1
		if encoding == "gzip" {
			return accepted
		}
		if encoding == "*" {
			wildcard = accepted
		}
	}
	return wildcard
}

func writeMissingUI(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"web UI is not built; API is available under /api"}` + "\n"))
}
