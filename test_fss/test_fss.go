package main

import (
	"fmt"
	"github.com/frankw2/libfss"
)

func main() {
	// Generate fss Keys on client
	fClient := libfss.ClientInitialize(6)
	fssKeys := fClient.GenerateTreePF(10, 2)

	// Simulate server
	fServer := libfss.ServerInitialize(fClient.PrfKeys, fClient.NumBits)
	ans0 := fServer.EvaluatePF(0, fssKeys[0], 9)
	ans1 := fServer.EvaluatePF(1, fssKeys[1], 9)
	fmt.Println(ans0 + ans1)
}
