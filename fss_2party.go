package libfss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

type Fss struct {
	// store keys used in fixedBlocks so that they can be sent to the server
	prfKeys     [][]byte
	fixedBlocks []cipher.Block
	N           uint
	numBits     uint   // number of bits in domain
	temp        []byte // temporary slices so that we only need to allocate memory at the beginning
	out         []byte
}

type FssKey struct {
	sInit   []byte
	tInit   byte
	cw      [][]byte // there are n
	finalCW int
}

const initPRFLen int = 4

// initialize client with this function
func (f Fss) clientInitialize(numBits uint) {
	f.numBits = numBits
	f.prfKeys = make([][]byte, initPRFLen)
	// Create fixed AES blocks
	f.fixedBlocks = make([]cipher.Block, initPRFLen)
	for i := 0; i < initPRFLen; i++ {
		f.prfKeys[i] = make([]byte, aes.BlockSize)
		rand.Read(f.prfKeys[i])
		block, err := aes.NewCipher(f.prfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.fixedBlocks[i] = block
	}
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.temp = make([]byte, aes.BlockSize)
	f.out = make([]byte, aes.BlockSize*4)
}

// upon receiving query from server, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func (f Fss) serverInitialize(prfKeys [][]byte, numBits uint) {
	f.numBits = numBits
	for i := range prfKeys {
		f.prfKeys[i] = prfKeys[i]
		block, err := aes.NewCipher(f.prfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.fixedBlocks[i] = block
	}
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
}

// Generate Keys for point functions
func (f Fss) generateTreePF(a uint, b uint) []FssKey {
	fssKeys := make([]FssKey, 2)
	// Set up initial values
	tempRand1 := make([]byte, aes.BlockSize+1)
	rand.Read(tempRand1)
	fssKeys[0].sInit = tempRand1[:aes.BlockSize]
	fssKeys[0].tInit = tempRand1[aes.BlockSize] % 2
	fssKeys[1].sInit = make([]byte, aes.BlockSize)
	rand.Read(fssKeys[1].sInit)
	fssKeys[1].tInit = (fssKeys[0].tInit + 1) % 2

	// Set current seed being used
	sCurr0 := fssKeys[0].sInit
	sCurr1 := fssKeys[1].sInit
	tCurr0 := fssKeys[0].tInit
	tCurr1 := fssKeys[1].tInit

	// Initialize correction words in FSS keys
	fssKeys[0].cw = make([][]byte, f.numBits)
	fssKeys[1].cw = make([][]byte, f.numBits)
	for i := uint(0); i < f.numBits; i++ {
		// make AES block size + 2 bytes
		fssKeys[0].cw[i] = make([]byte, aes.BlockSize+2)
		fssKeys[1].cw[i] = make([]byte, aes.BlockSize+2)
	}

	leftStart := 0
	rightStart := aes.BlockSize + 1
	for i := uint(0); i < f.numBits; i++ {
		// "expand" seed into two seeds + 2 bits
		prf(sCurr0, f.fixedBlocks, 3, f.temp, f.out)
		prfOut0 := make([]byte, aes.BlockSize*3)
		copy(prfOut0, f.out[:aes.BlockSize*3])
		prf(sCurr1, f.fixedBlocks, 3, f.temp, f.out)
		prfOut1 := make([]byte, aes.BlockSize*3)
		copy(prfOut1, f.out[:aes.BlockSize*3])

		// Parse out "t" bits
		t0Left := prfOut0[aes.BlockSize] % 2
		t0Right := prfOut0[(aes.BlockSize*2)+1] % 2
		t1Left := prfOut1[aes.BlockSize] % 2
		t1Right := prfOut1[(aes.BlockSize*2)+1] % 2
		// Find bit in a
		aBit := getBit(a, i, f.N)

		// Figure out which half of expanded seeds to keep and lose
		keep := rightStart
		lose := leftStart
		if a == 0 {
			keep = leftStart
			lose = rightStart
		}
		// Set correction words for both keys. Note: they are the same
		for j := 0; j < aes.BlockSize; j++ {
			fssKeys[0].cw[i][j] = prfOut0[lose+j] ^ prfOut1[lose+j]
			fssKeys[1].cw[i][j] = fssKeys[0].cw[i][j]
		}
		fssKeys[0].cw[i][aes.BlockSize] = t0Left ^ t1Left ^ aBit ^ 1
		fssKeys[1].cw[i][aes.BlockSize] = fssKeys[0].cw[i][aes.BlockSize]
		fssKeys[0].cw[i][aes.BlockSize+1] = t0Right ^ t1Right ^ aBit
		fssKeys[1].cw[i][aes.BlockSize+1] = fssKeys[0].cw[i][aes.BlockSize+1]

		for j := 0; j < aes.BlockSize; j++ {
			sCurr0[j] = prfOut0[keep+j] ^ (tCurr0 * fssKeys[0].cw[i][j])
			sCurr1[j] = prfOut1[keep+j] ^ (tCurr1 * fssKeys[0].cw[i][j])
		}
		tCWKeep := fssKeys[0].cw[i][aes.BlockSize]
		if keep == rightStart {
			tCWKeep = fssKeys[0].cw[i][aes.BlockSize+1]
		}
		tCurr0 = (prfOut0[keep+aes.BlockSize] % 2) ^ (tCWKeep * tCurr0)
		tCurr1 = (prfOut1[keep+aes.BlockSize] % 2) ^ (tCWKeep * tCurr1)
	}
	// Convert final CW to integer
	sFinal0, _ := binary.Varint(sCurr0[:8])
	sFinal1, _ := binary.Varint(sCurr1[:8])
	fssKeys[0].finalCW = int(b) - int(sFinal0) + int(sFinal1)
	fssKeys[1].finalCW = -1 * fssKeys[0].finalCW
	return fssKeys
}

func (f Fss) evaluatePF(b byte, k FssKey, x uint) int {
	sCurr := k.sInit
	tCurr := k.tInit
	for i := uint(0); i < f.numBits; i++ {
		prf(sCurr, f.fixedBlocks, 3, f.temp, f.out)
		for j := 0; j < aes.BlockSize+2; j++ {
			f.out[j] = f.out[j] ^ (tCurr * k.cw[i][j])
		}
		xBit := getBit(x, i, f.N)
		// Pick right seed expansion based on
		if xBit == 0 {
			sCurr = f.out[:aes.BlockSize]
			tCurr = f.out[aes.BlockSize]
		} else {
			sCurr = f.out[(aes.BlockSize + 1):(aes.BlockSize*2 + 1)]
			tCurr = f.out[aes.BlockSize*2+1]
		}
	}
	sFinal, _ := binary.Varint(sCurr[:8])
	if b == 0 {
		return int(sFinal) + int(tCurr)*k.finalCW
	} else {
		return -1 * (int(sFinal) + int(tCurr)*k.finalCW)
	}
}
