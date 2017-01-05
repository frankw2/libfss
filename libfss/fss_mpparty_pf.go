package libfss

// This file has functions for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

import (
	"crypto/rand"
	"math"
)

type FssKeyEqMP struct {
	NumParties uint
	CW         []uint32 //Assume CW is 32-bit because f.M is 4. If you change f.M, you should change this
	Sigma      [][]byte
}

func (f Fss) GenerateTreeEqMP(a, b, num_p uint) []FssKeyEqMP {
	keys := make([]FssKeyEqMP, num_p)
	p2 := uint(math.Pow(2, float64(num_p-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(num_p-1)/2.0)))
	v := uint(math.Ceil(math.Pow(2, float64(f.NumBits)) / float64(mu)))

	//delta := a & ((1 << (f.NumBits / 2)) - 1)
	gamma := (a & ((1<<(f.NumBits+1)/2 - 1) << f.NumBits / 2)) >> f.NumBits / 2
	aArr := make([][][]byte, v)
	for i := uint(0); i < v; i++ {
		aArr[i] = make([][]byte, num_p)
		for j := uint(0); j < num_p; j++ {
			aArr[i][j] = make([]byte, p2)
		}
	}
	for i := uint(0); i < v; i++ {
		for j := uint(0); j < num_p; j++ {
			if j != (num_p - 1) {
				rand.Read(aArr[i][j])
				for k := uint(0); k < p2; k++ {
					aArr[i][j][k] = aArr[i][j][k] % 2
				}
			} else {
				for k := uint(0); k < p2; k++ {
					curr_bits := uint(0)
					for l := uint(0); l < num_p-1; l++ {
						curr_bits += uint(aArr[i][l][k])
					}
					curr_bits = curr_bits % 2
					if i != gamma {
						if curr_bits == 0 {
							aArr[i][j][k] = 0
						} else {
							aArr[i][j][k] = 1
						}
					} else {
						if curr_bits == 0 {
							aArr[i][j][k] = 1
						} else {
							aArr[i][j][k] = 0
						}
					}
				}
			}
		}
	}
	//s := make([][][]byte, v)
	for i := uint(0); i < v; i++ {

	}

	return keys
}
