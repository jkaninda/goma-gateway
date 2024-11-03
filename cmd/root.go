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
	"github.com/jkaninda/goma-gateway/cmd/config"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/spf13/cobra"
)

// rootCmd represents
var rootCmd = &cobra.Command{
	Use:     "goma",
	Short:   "Goma Gateway is a lightweight API Gateway, Reverse Proxy",
	Long:    `.`,
	Example: util.MainExample,
	Version: util.FullVersion(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		logger.Fatal("Error executing root command %v", err)
	}
}
func init() {
	rootCmd.AddCommand(ServerCmd)
	rootCmd.AddCommand(config.Cmd)
	rootCmd.AddCommand(VersionCmd)

}
