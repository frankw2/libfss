package libfss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Initialize functions for client and server
// You should initialize after each query on the database like in
// Private Information Retrieval (PIR)

// initialize client with this function
// numBits represents the input domain for the function, i.e. the number
// of bits to check
func ClientInitialize(numBits uint) *Fss {
	f := new(Fss)
	f.NumBits = numBits
	f.PrfKeys = make([][]byte, initPRFLen)
	// Create fixed AES blocks
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := 0; i < initPRFLen; i++ {
		f.PrfKeys[i] = make([]byte, aes.BlockSize)
		rand.Read(f.PrfKeys[i])
		//fmt.Println("client")
		//fmt.Println(f.PrfKeys[i])
		block, err := aes.NewCipher(f.PrfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)
	return f
}

// upon receiving query from server, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func ServerInitialize(prfKeys [][]byte, numBits uint) *Fss {
	f := new(Fss)
	f.NumBits = numBits
	f.PrfKeys = make([][]byte, initPRFLen)
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := range prfKeys {
		f.PrfKeys[i] = make([]byte, aes.BlockSize)
		copy(f.PrfKeys[i], prfKeys[i])
		//fmt.Println("server")
		//fmt.Println(f.PrfKeys[i])
		block, err := aes.NewCipher(f.PrfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)

	return f
}
