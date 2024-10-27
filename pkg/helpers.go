package pkg

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jkaninda/goma-gateway/util"
)

func Intro() {
	nameFigure := figure.NewFigure("Goma", "", true)
	nameFigure.Print()
	fmt.Printf("Version: %s\n", util.FullVersion())
	fmt.Println("Copyright (c) 2024 Jonas Kaninda")
	fmt.Println("Starting Goma Gateway server...")
}
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Route", "Rewrite", "Destination"})
	for _, route := range routes {
		t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
	}
	fmt.Println(t.Render())
}
