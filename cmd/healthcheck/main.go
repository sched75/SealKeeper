// Command healthcheck is a tiny self-contained probe baked into the distroless
// runtime image. The image ships no curl or wget, so the Docker / Kubernetes
// HEALTHCHECK and the smoke tests rely on this binary.
//
// It performs a single GET against HEALTHCHECK_URL (default
// http://127.0.0.1:8443/healthz) and exits 0 on HTTP 200, 1 otherwise.
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	target := os.Getenv("HEALTHCHECK_URL")
	if target == "" {
		target = "http://127.0.0.1:8443/healthz"
	}
	cli := &http.Client{Timeout: 3 * time.Second}
	r, err := cli.Get(target)
	if err != nil {
		os.Exit(1)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
