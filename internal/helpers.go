package pkg

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Path", "Rewrite", "Destination"})
	for _, route := range routes {
		if len(route.Backends) != 0 {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, fmt.Sprintf("backends: [%d]", len(route.Backends))})

		} else {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
		}
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

func (oauth *OauthRulerMiddleware) getUserInfo(token *oauth2.Token) (UserInfo, error) {
	oauthConfig := oauth2Config(oauth)
	// Call the user info endpoint with the token
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get(oauth.Endpoint.UserInfoURL)
	if err != nil {
		return UserInfo{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Parse the user info
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, err
	}

	return userInfo, nil
}
