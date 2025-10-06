/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cmd

import (
	"fmt"
	"github.com/jkaninda/goma-gateway/cmd/config"
	"github.com/jkaninda/goma-gateway/pkg/version"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/spf13/cobra"
	"os"
)

// rootCmd represents
var rootCmd = &cobra.Command{
	Use:     "goma",
	Short:   "Goma Gateway is a lightweight API Gateway Management",
	Long:    "Goma Gateway is a lightweight, high-performance,security-focused API Gateway Management",
	Example: util.MainExample,
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {
		ServerCmd.Run(cmd, args)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Printf("Error executing root command %v\n", err)
		os.Exit(1)
	}
}
func init() {
	rootCmd.AddCommand(ServerCmd)
	rootCmd.AddCommand(config.Cmd)
	rootCmd.AddCommand(VersionCmd)
	rootCmd.Flags().StringP("config", "c", "", "Path to the configuration filename")

}
