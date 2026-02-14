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

package version

import "fmt"

const ConfigVersion = "2"

var Version = "development"
var buildTime string
var gitCommit string

func FullVersion() {
	fmt.Printf("Goma Gateway version: %s\n", Version)
	fmt.Printf("Configuration version: %s\n", ConfigVersion)
	fmt.Printf("Build time: %s\n", buildTime)
	fmt.Printf("Git commit: %s\n", gitCommit)
}

var Banner = `
   ____                       
  / ___| ___  _ __ ___   __ _ 
 | |  _ / _ \| '_ ` + "`" + ` _ \ / _` + "`" + ` |
 | |_| | (_) | | | | | | (_| |
  \____|\___/|_| |_| |_|\__,_|
  :: Goma Gateway :: - (` + Version + `)
`

func PrintBanner() {
	fmt.Print(Banner)
	fmt.Println("Copyright (c) 2024-2026 Jonas Kaninda")
	fmt.Println("Starting Goma Gateway...")
}
