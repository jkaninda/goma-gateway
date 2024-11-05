package pkg

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"crypto/tls"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net/http"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Route", "Rewrite", "Destination"})
	for _, route := range routes {
		t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
	}
	fmt.Println(t.Render())
}

// getRealIP gets user real IP
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// loadTLS loads TLS Certificate
func loadTLS(cert, key string) (*tls.Config, error) {
	if cert == "" && key == "" {
		return nil, fmt.Errorf("no certificate or key file provided")
	}
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		logger.Error("Error loading server certificate: %v", err)
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	return tlsConfig, nil
}
