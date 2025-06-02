// Package cmd /
/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/jkaninda/goma-gateway/internal"
	"github.com/jkaninda/goma-gateway/internal/version"
	"github.com/spf13/cobra"
	"os"
)

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start server",
	Run: func(cmd *cobra.Command, args []string) {
		intro()
		configFile, _ := cmd.Flags().GetString("config")
		if configFile == "" {
			configFile = internal.GetConfigPaths()
		}
		ctx := context.Background()
		g := internal.GatewayServer{}
		gs, err := g.Config(configFile, ctx)
		if err != nil {
			fmt.Printf("Could not load configuration: %v\n", err)
			os.Exit(1)
		}
		gs.InitLogger()
		if err := gs.Start(); err != nil {
			fmt.Printf("Could not start server: %v\n", err)
			os.Exit(1)

		}

	},
}

func init() {
	ServerCmd.Flags().StringP("config", "c", "", "Path to the configuration filename")
}
func intro() {
	nameFigure := figure.NewFigure("Goma", "", true)
	nameFigure.Print()
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Println("Copyright (c) 2024 Jonas Kaninda")
	fmt.Println("Starting Goma Gateway server...")
}
