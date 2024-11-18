package util

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"fmt"
)

const ConfigVersion = "1.0"

var Version = "development"
var buildTime string
var gitCommit string

func FullVersion() {
	fmt.Printf("Goma Gateway version: %s\n", Version)
	fmt.Printf("Configuration version: %s\n", ConfigVersion)
	fmt.Printf("Build time: %s\n", buildTime)
	fmt.Printf("Git commit: %s\n", gitCommit)
}

const MainExample = "Initialize config: config init --output config.yml\n" +
	"Start server: server \n" +
	"Start server with custom config file: server --config config.yml \n" +
	"Check config file: config check --config config.yml"
