package pkg

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"net/http"
)

func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Route", "Rewrite", "Destination"})
	for _, route := range routes {
		t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
	}
	fmt.Println(t.Render())
}
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
