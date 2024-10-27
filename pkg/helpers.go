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
	"github.com/jkaninda/goma-gateway/util"
)

func Intro() {
	nameFigure := figure.NewFigure("Goma", "", true)
	nameFigure.Print()
	fmt.Printf("Version: %s\n", util.FullVersion())
	fmt.Println("Copyright (c) 2024 Jonas Kaninda")
	fmt.Println("Starting Goma Gateway server...")
}
