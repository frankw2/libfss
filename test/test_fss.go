package main

import (
	//"fmt"
	"github.com/frankw2/libfss"
)

func main() {
	f := new(libfss.Fss)
	f.clientInitialize(10)
	fssKeys := generateTreePF(10, 1)
}
