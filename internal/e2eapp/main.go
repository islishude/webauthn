package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "HTTPS listen address")
	host := flag.String("host", "webauthn.test", "RP ID and test host")
	flag.Parse()

	app, err := newApp(*host)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig, err := selfSignedTLSConfig(*host)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           app.routes(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("e2e app listening on https://%s", *addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
