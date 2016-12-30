package main

import (
	"fmt"
	"github.com/frankw2/libfss"
)

func main() {
	// Generate fss Keys on client
	fClient := new(libfss.Fss)
	fClient.ClientInitialize(10)
	fssKeys := fClient.GenerateTreePF(10, 5)

	// Simulate server
	fServer := new(libfss.Fss)
	fServer.ServerInitialize(fClient.PrfKeys, fClient.NumBits)
	ans0 := fServer.EvaluatePF(0, fssKeys[0], 10)
	ans1 := fServer.EvaluatePF(1, fssKeys[1], 10)
	fmt.Println(ans0 + ans1)
}
