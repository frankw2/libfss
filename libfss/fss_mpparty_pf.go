package libfss

// This file has functions for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"math"
)

type FssKeyEqMP struct {
	NumParties uint
	CW         [][]uint32 //Assume CW is 32-bit because f.M is 4. If you change f.M, you should change this
	Sigma      [][]byte
}

func (f Fss) GenerateTreeEqMP(a, b, num_p uint) []FssKeyEqMP {
	keys := make([]FssKeyEqMP, num_p)
	p2 := uint(math.Pow(2, float64(num_p-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(num_p-1)/2.0)))
	v := uint(math.Ceil(math.Pow(2, float64(f.NumBits)) / float64(mu)))

	delta := a & ((1 << (f.NumBits / 2)) - 1)
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

	s := make([][][]byte, v)
	for i := uint(0); i < v; i++ {
		s[i] = make([][]byte, p2)
		for j := uint(0); j < p2; j++ {
			s[i][j] = make([]byte, aes.BlockSize)
			rand.Read(s[i][j])
		}
	}

	cw := make([][]uint32, p2)
	cw_temp := make([]uint32, mu)
	cw_helper := make([]byte, f.M*mu)
	numBlocks := uint(math.Ceil(float64(f.M*mu) / float64(aes.BlockSize)))
	// Create correction words
	for i := uint(0); i < p2; i++ {
		prf(s[gamma][i], f.FixedBlocks, numBlocks, f.Temp, f.Out)
		for k := uint(0); k < mu; k++ {
			tempInt := binary.LittleEndian.Uint32(f.Out[f.M*k : f.M*k+f.M])
			cw_temp[k] = cw_temp[k] ^ tempInt
		}
		cw[i] = make([]uint32, mu)
		// The last CW has to fulfill a certain condition, so we deal with it separately
		if i == (p2 - 1) {
			break
		}
		rand.Read(cw_helper)
		for j := uint(0); j < mu; j++ {
			cw[i][j] = binary.LittleEndian.Uint32(cw_helper[f.M*j : f.M*j+f.M])
			cw_temp[j] = cw_temp[j] ^ cw[i][j]
		}
	}

	for i := uint(0); i < mu; i++ {
		if i == delta {
			cw[p2-1][i] = uint32(b) ^ cw_temp[i]
		} else {
			cw[p2-1][i] = cw_temp[i]
		}
	}

	sigma := make([][][]byte, num_p)
	for i := uint(0); i < num_p; i++ {
		// set number of parties in keys
		sigma[i] = make([][]byte, v)
		for j := uint(0); j < v; j++ {
			sigma[i][j] = make([]byte, aes.BlockSize*p2)
			for k := uint(0); k < p2; k++ {
				// if aArr[j][i][k] == 0, sigma[i][j] should be 0
				if aArr[j][i][k] != 0 {
					copy(sigma[i][j][k*aes.BlockSize:k*aes.BlockSize+aes.BlockSize], s[j][k])
				}
			}
		}
	}

	for i := uint(0); i < num_p; i++ {
		keys[i].Sigma = sigma[i]
		keys[i].CW = cw
		keys[i].NumParties = num_p
	}
	return keys
}

func (f Fss) EvaluateEqMP(k FssKeyEqMP, x uint) uint32 {
	p2 := uint(math.Pow(2, float64(k.NumParties-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(k.NumParties-1)/2)))

	delta := x & ((1 << (f.N / 2)) - 1)
	gamma := (x & (((1 << (f.N + 1) / 2) - 1) << f.N / 2)) >> f.N / 2
	mBytes := f.M * mu

	y := make([]uint32, mu)
	for i := uint(0); i < p2; i++ {
		s := k.Sigma[gamma][i*aes.BlockSize : i*aes.BlockSize+aes.BlockSize]
		all_zero_bytes := true
		for j := uint(0); j < aes.BlockSize; j++ {
			if s[j] != 0 {
				all_zero_bytes = false
				break
			}
		}
		if all_zero_bytes == false {
			numBlocks := uint(math.Ceil(float64(mBytes) / float64(aes.BlockSize)))
			prf(s, f.FixedBlocks, numBlocks, f.Temp, f.Out)
			for k := uint(0); k < mu; k++ {
				tempInt := binary.LittleEndian.Uint32(f.Out[f.M*k : f.M*k+f.M])
				y[k] = y[k] ^ tempInt
			}
			for j := uint(0); j < mu; j++ {
				y[j] = k.CW[i][j] ^ y[j]
			}
		}
	}
	return y[delta]
}
