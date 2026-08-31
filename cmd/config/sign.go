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

	"github.com/jkaninda/goma-gateway/internal"
	"github.com/spf13/cobra"
)

// SigningKeygenCmd mints the keypair used to sign provider bundles.
var SigningKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 keypair for signing provider configuration bundles",
	Long: "Generate an Ed25519 keypair for signing provider configuration bundles.\n\n" +
		"Put the public key in the gateway's providers.signing.publicKey, and keep the\n" +
		"private key wherever bundles are published from. Once a public key is\n" +
		"configured, the gateway refuses any HTTP or Git bundle that is not signed by it.",
	Run: func(cmd *cobra.Command, _ []string) {
		publicKey, privateKey, err := internal.GenerateBundleSigningKey()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if out, _ := cmd.Flags().GetString("output"); out != "" {
			if err := os.WriteFile(out, []byte(privateKey+"\n"), 0600); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Private key written to %s (mode 0600)\n", out)
		} else {
			fmt.Printf("Private key (keep this secret): %s\n", privateKey)
		}
		fmt.Printf("Public key  (providers.signing.publicKey): %s\n", publicKey)
	},
}

// SignConfigCmd signs a bundle in place.
var SignConfigCmd = &cobra.Command{
	Use:   "sign [bundle...]",
	Short: "Sign provider configuration bundles in place",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key, _ := cmd.Flags().GetString("key")
		keyFile, _ := cmd.Flags().GetString("key-file")

		switch {
		case key == "" && keyFile == "":
			// Prefer the environment over an argument: a key passed on the
			// command line ends up in the shell history and in ps output.
			key = os.Getenv("GOMA_BUNDLE_SIGNING_KEY")
			if key == "" {
				fmt.Println("Error: provide --key-file, or set GOMA_BUNDLE_SIGNING_KEY")
				os.Exit(1)
			}
		case keyFile != "":
			contents, err := os.ReadFile(keyFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			key = string(contents)
		}

		for _, path := range args {
			if err := internal.SignBundleFile(path, key); err != nil {
				fmt.Printf("%s: %v\n", path, err)
				os.Exit(1)
			}
			fmt.Printf("Signed %s\n", path)
		}
	},
}

func init() {
	SigningKeygenCmd.Flags().StringP("output", "o", "", "write the private key to this file instead of stdout")
	SignConfigCmd.Flags().String("key", "", "base64 Ed25519 private key (prefer --key-file or GOMA_BUNDLE_SIGNING_KEY)")
	SignConfigCmd.Flags().String("key-file", "", "file holding the base64 Ed25519 private key")
}
