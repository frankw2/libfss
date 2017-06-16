package main

import (
	"fmt"
	"github.com/frankw2/go/libfss"
)

func main() {
	// Generate fss Keys on client
	fClient := libfss.ClientInitialize(6)
	// Test with if x = 10, evaluate to 2
	fssKeys := fClient.GenerateTreePF(10, 2)

	// Simulate server
	fServer := libfss.ServerInitialize(fClient.PrfKeys, fClient.NumBits)

	// Test 2-party Equality Function
	var ans0, ans1 int = 0, 0
	ans0 = fServer.EvaluatePF(0, fssKeys[0], 10)
	ans1 = fServer.EvaluatePF(1, fssKeys[1], 10)
	fmt.Println("Match (should be non-zero):", ans0+ans1)

	ans0 = fServer.EvaluatePF(0, fssKeys[0], 11)
	ans1 = fServer.EvaluatePF(1, fssKeys[1], 11)
	fmt.Println("No Match (should be 0):", ans0+ans1)

	ans0 = fServer.EvaluatePF(0, fssKeys[0], 9)
	ans1 = fServer.EvaluatePF(1, fssKeys[1], 9)
	fmt.Println("No Match (should be 0):", ans0+ans1)

	// Test 2-party Less than Function
	// Test if x < 10, evaluate to 2
	fssKeysLt := fClient.GenerateTreeLt(10, 2)

	var anslt0, anslt1 uint = 0, 0
	anslt0 = fServer.EvaluateLt(fssKeysLt[0], 8)
	anslt1 = fServer.EvaluateLt(fssKeysLt[1], 8)
	fmt.Println("Less than (should be non-zero):", anslt0-anslt1)
	anslt0 = fServer.EvaluateLt(fssKeysLt[0], 11)
	anslt1 = fServer.EvaluateLt(fssKeysLt[1], 11)
	fmt.Println("Greater than (should be zero):", anslt0-anslt1)

	// Test multiparty equal function case
	fssKeysEqMP := fServer.GenerateTreeEqMP(10, 2, 3)

	var ansEqMP0, ansEqMP1, ansEqMP2 uint32 = 0, 0, 0
	ansEqMP0 = fServer.EvaluateEqMP(fssKeysEqMP[0], 10)
	ansEqMP1 = fServer.EvaluateEqMP(fssKeysEqMP[1], 10)
	ansEqMP2 = fServer.EvaluateEqMP(fssKeysEqMP[2], 10)

	fmt.Println("Multi-party Equal Match (should be non-zero):", ansEqMP0^ansEqMP1^ansEqMP2)

	ansEqMP0 = fServer.EvaluateEqMP(fssKeysEqMP[0], 12)
	ansEqMP1 = fServer.EvaluateEqMP(fssKeysEqMP[1], 12)
	ansEqMP2 = fServer.EvaluateEqMP(fssKeysEqMP[2], 12)
	fmt.Println("Multi-party Equal not Match (should be zero):", ansEqMP0^ansEqMP1^ansEqMP2)

}
