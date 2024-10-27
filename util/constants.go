package util

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"os"
)

var Version string

func VERSION(def string) string {
	build := os.Getenv("VERSION")
	if build == "" {
		return def
	}
	return build
}
func FullVersion() string {
	ver := Version
	if b := VERSION(""); b != "" {
		return b
	}
	return ver
}
