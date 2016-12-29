package libfss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Fss struct {
	// store keys used in fixedBlocks so that they can be sent to the server
	prfKeys     [][]byte
	fixedBlocks []cipher.Block
}

const initPRFLen int = 4

// initialize client with this function
func (f Fss) clientInitialize() {
	// Create fixed AES blocks
	f.fixedBlocks = make([]cipher.Block, initPRFLen)
	for i := 0; i < initPRFLen; i++ {
		f.prfKeys[i] = make([]byte, initPRFLen)
		rand.Read(f.prfKeys[i])
		block, err := aes.NewCipher(f.prfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.fixedBlocks[i] = block
	}
}

// upon receiving query from server, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func (f Fss) serverInitialize(prfKeys [][]bytes) {
	for i := range prfKeys {
		f.prfKeys[i] = prfKeys[i]
		block, err := aes.NewCipher(f.prfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.fixedBlocks[i] = block
	}
}

func prf(x []byte, aesBlocks []cipher.Block, outSize int) []byte {
	temp := make([]byte, 16)
	out := make([]byte, outSize)
	for i := range aesBlocks {
		// get AES_k[i](x)
		block.Encrypt(temp, x)
		// get AES_k[i](x) ^ x
		for j := range temp {
			out[i*16+j] = temp[j] ^ x[j]
		}
	}
	return out
}
