// Ingest gateway: accepts high-volume POST batches and forwards to NARIP REST (fan-out pattern).
package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	upstream := os.Getenv("NARIP_UPSTREAM")
	if upstream == "" {
		upstream = "http://127.0.0.1:8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"narip-ingest-gateway"}`))
	})
	mux.HandleFunc("/v1/ingest/forward", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		req, err := http.NewRequest(http.MethodPost, upstream+"/v1/risk/score", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "upstream build error", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	addr := ":8081"
	log.Printf("ingest-gateway listening on %s -> %s", addr, upstream)
	log.Fatal(http.ListenAndServe(addr, mux))
}
