// Command quickstart runs a localhost-only, single-account passkey demo.
package main

import (
	"errors"
	"log"
	"net/http"
	"time"
)

func main() {
	a, err := newApp()
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	log.Print("Open http://localhost:8080 (single demo account; memory is lost on restart)")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
