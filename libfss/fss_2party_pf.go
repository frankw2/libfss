package libfss

// This file has the generate and evaluate functions
// for a 2 party point function FSS scheme.
// This is based on the following paper:
// Boyle, Elette, Niv Gilboa, and Yuval Ishai. "Function Secret Sharing: Improvements and Extensions." Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2016.

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	//"fmt"
)

type FssKeyEq2P struct {
	SInit   []byte
	TInit   byte
	CW      [][]byte // there are n
	FinalCW int
}

// Generate Keys for 2-party point functions
// It creates keys for a function that evaluates to b when input x = a.

func (f Fss) GenerateTreePF(a, b uint) []FssKeyEq2P {
	fssKeys := make([]FssKeyEq2P, 2)
	// Set up initial values
	tempRand1 := make([]byte, aes.BlockSize+1)
	rand.Read(tempRand1)
	fssKeys[0].SInit = tempRand1[:aes.BlockSize]
	fssKeys[0].TInit = tempRand1[aes.BlockSize] % 2
	fssKeys[1].SInit = make([]byte, aes.BlockSize)
	rand.Read(fssKeys[1].SInit)
	fssKeys[1].TInit = fssKeys[0].TInit ^ 1

	// Set current seed being used
	sCurr0 := make([]byte, aes.BlockSize)
	sCurr1 := make([]byte, aes.BlockSize)
	copy(sCurr0, fssKeys[0].SInit)
	copy(sCurr1, fssKeys[1].SInit)
	tCurr0 := fssKeys[0].TInit
	tCurr1 := fssKeys[1].TInit

	// Initialize correction words in FSS keys
	fssKeys[0].CW = make([][]byte, f.NumBits)
	fssKeys[1].CW = make([][]byte, f.NumBits)
	for i := uint(0); i < f.NumBits; i++ {
		// make AES block size + 2 bytes
		fssKeys[0].CW[i] = make([]byte, aes.BlockSize+2)
		fssKeys[1].CW[i] = make([]byte, aes.BlockSize+2)
	}

	leftStart := 0
	rightStart := aes.BlockSize + 1
	for i := uint(0); i < f.NumBits; i++ {
		// "expand" seed into two seeds + 2 bits
		prf(sCurr0, f.FixedBlocks, 3, f.Temp, f.Out)
		prfOut0 := make([]byte, aes.BlockSize*3)
		copy(prfOut0, f.Out[:aes.BlockSize*3])
		prf(sCurr1, f.FixedBlocks, 3, f.Temp, f.Out)
		prfOut1 := make([]byte, aes.BlockSize*3)
		copy(prfOut1, f.Out[:aes.BlockSize*3])

		//fmt.Println(i, sCurr0)
		//fmt.Println(i, sCurr1)
		// Parse out "t" bits
		t0Left := prfOut0[aes.BlockSize] % 2
		t0Right := prfOut0[(aes.BlockSize*2)+1] % 2
		t1Left := prfOut1[aes.BlockSize] % 2
		t1Right := prfOut1[(aes.BlockSize*2)+1] % 2
		// Find bit in a
		aBit := getBit(a, (f.N - f.NumBits + i + 1), f.N)

		// Figure out which half of expanded seeds to keep and lose
		keep := rightStart
		lose := leftStart
		if aBit == 0 {
			keep = leftStart
			lose = rightStart
		}
		//fmt.Println("keep", keep)
		//fmt.Println("aBit", aBit)
		// Set correction words for both keys. Note: they are the same
		for j := 0; j < aes.BlockSize; j++ {
			fssKeys[0].CW[i][j] = prfOut0[lose+j] ^ prfOut1[lose+j]
			fssKeys[1].CW[i][j] = fssKeys[0].CW[i][j]
		}
		fssKeys[0].CW[i][aes.BlockSize] = t0Left ^ t1Left ^ aBit ^ 1
		fssKeys[1].CW[i][aes.BlockSize] = fssKeys[0].CW[i][aes.BlockSize]
		fssKeys[0].CW[i][aes.BlockSize+1] = t0Right ^ t1Right ^ aBit
		fssKeys[1].CW[i][aes.BlockSize+1] = fssKeys[0].CW[i][aes.BlockSize+1]

		for j := 0; j < aes.BlockSize; j++ {
			sCurr0[j] = prfOut0[keep+j] ^ (tCurr0 * fssKeys[0].CW[i][j])
			sCurr1[j] = prfOut1[keep+j] ^ (tCurr1 * fssKeys[0].CW[i][j])
		}
		//fmt.Println("sKeep0:", prfOut0[keep:keep+aes.BlockSize])
		//fmt.Println("sKeep1:", prfOut1[keep:keep+aes.BlockSize])
		tCWKeep := fssKeys[0].CW[i][aes.BlockSize]
		if keep == rightStart {
			tCWKeep = fssKeys[0].CW[i][aes.BlockSize+1]
		}
		tCurr0 = (prfOut0[keep+aes.BlockSize] % 2) ^ tCWKeep*tCurr0
		tCurr1 = (prfOut1[keep+aes.BlockSize] % 2) ^ tCWKeep*tCurr1
	}
	// Convert final CW to integer
	sFinal0, _ := binary.Varint(sCurr0[:8])
	sFinal1, _ := binary.Varint(sCurr1[:8])
	fssKeys[0].FinalCW = (int(b) - int(sFinal0) + int(sFinal1))
	fssKeys[1].FinalCW = fssKeys[0].FinalCW
	if tCurr1 == 1 {
		fssKeys[0].FinalCW = fssKeys[0].FinalCW * -1
		fssKeys[1].FinalCW = fssKeys[0].FinalCW
	}
	return fssKeys
}

// Each of the 2 server calls this function to evaluate their function
// share on a value. Then, the client adds the results from both servers.
func (f Fss) EvaluatePF(serverNum byte, k FssKeyEq2P, x uint) int {
	sCurr := make([]byte, aes.BlockSize)
	copy(sCurr, k.SInit)
	tCurr := k.TInit
	for i := uint(0); i < f.NumBits; i++ {
		prf(sCurr, f.FixedBlocks, 3, f.Temp, f.Out)
		//fmt.Println(i, sCurr)
		//fmt.Println(i, "f.Out:", f.Out)
		// Keep counter to ensure we are accessing CW correctly
		count := 0
		for j := 0; j < aes.BlockSize*2+2; j++ {
			// Make sure we are doing G(s) ^ (t*sCW||tLCW||sCW||tRCW)
			if j == aes.BlockSize+1 {
				count = 0
			} else if j == aes.BlockSize*2+1 {
				count = aes.BlockSize + 1
			}
			f.Out[j] = f.Out[j] ^ (tCurr * k.CW[i][count])
			count++
		}
		xBit := getBit(x, (f.N - f.NumBits + i + 1), f.N)
		//fmt.Println("xBit", xBit)
		// Pick right seed expansion based on
		if xBit == 0 {
			copy(sCurr, f.Out[:aes.BlockSize])
			tCurr = f.Out[aes.BlockSize] % 2
		} else {
			copy(sCurr, f.Out[(aes.BlockSize+1):(aes.BlockSize*2+1)])
			tCurr = f.Out[aes.BlockSize*2+1] % 2
		}
		//fmt.Println(f.Out)
	}
	sFinal, _ := binary.Varint(sCurr[:8])
	if serverNum == 0 {
		return int(sFinal) + int(tCurr)*k.FinalCW
	} else {
		return -1 * (int(sFinal) + int(tCurr)*k.FinalCW)
	}
}
