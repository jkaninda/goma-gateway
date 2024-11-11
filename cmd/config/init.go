package config

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
import (
	"fmt"
	"github.com/jkaninda/goma-gateway/internal"
	"github.com/spf13/cobra"
	"os"
)

var InitConfigCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Goma Gateway configuration file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			force, _ := cmd.Flags().GetBool("force")
			configFile, _ := cmd.Flags().GetString("output")
			if configFile == "" {
				fmt.Println("Error: no config file specified")
				os.Exit(1)
			}
			// Check if the config file exists
			if _, err := os.Stat(configFile); !os.IsNotExist(err) {
				if !force {
					fmt.Printf("%s config file already exists, use -f to overwrite\n", configFile)
					os.Exit(1)
				}
			}
			err := pkg.InitConfig(configFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("configuration file has been initialized successfully")
		} else {
			fmt.Printf("config accepts no argument %q\n", args)
			os.Exit(1)
		}

	},
}

func init() {
	InitConfigCmd.Flags().StringP("output", "o", "", "configuration file output")
	InitConfigCmd.Flags().BoolP("force", "f", false, "Force overwrite configuration file")
}
