package libfss

import (
	"crypto/aes"
	"crypto/cipher"
)

// 0th position is the most significant bit
// True if bit is 1 and False if bit is 0
// N is the number of bits in uint
func getBit(n, pos, N uint) byte {
	val := (n & (1 << (N - pos)))
	if val > 0 {
		return 1
	} else {
		return 0
	}
}

// fixed key PRF (Matyas–Meyer–Oseas one way compression function)
// numBlocks represents the number
func prf(x []byte, aesBlocks []cipher.Block, numBlocks uint, temp, out []byte) {
	for i := uint(0); i < numBlocks; i++ {
		// get AES_k[i](x)
		aesBlocks[i].Encrypt(temp, x)
		// get AES_k[i](x) ^ x
		for j := range temp {
			out[i*aes.BlockSize+uint(j)] = temp[j] ^ x[j]
		}
	}
}
