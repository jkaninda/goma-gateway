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

package config

import (
	"fmt"
	"os"

	pkg "github.com/jkaninda/goma-gateway/internal"
	"github.com/spf13/cobra"
)

var CheckConfigCmd = &cobra.Command{
	Use:   "check",
	Short: "Check Goma Gateway configuration file",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		if configFile == "" {
			fmt.Println("no config file specified")
			os.Exit(1)
		}
		err := pkg.CheckConfig(configFile)
		if err != nil {
			fmt.Printf(" Error checking config file: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("Goma Gateway configuration file checked successfully")

	},
}

func init() {
	CheckConfigCmd.Flags().StringP("config", "c", "", "Path to the configuration filename")
}
