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

	var ans0, ans1 int = 0, 0
	ans0 = fServer.EvaluatePF(0, fssKeys[0], 10)
	ans1 = fServer.EvaluatePF(1, fssKeys[1], 10)
	fmt.Println("Match (should be non-zero):", ans0+ans1)

	ans0 = fServer.EvaluatePF(0, fssKeys[0], 11)
	ans1 = fServer.EvaluatePF(1, fssKeys[1], 11)
	fmt.Println("No Match (should be 0):", ans0+ans1)
}
