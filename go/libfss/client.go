package libfss

// This file contains all the client code for the FSS scheme.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	//"fmt"
	"math"
)

// Initialize client with this function
// numBits represents the input domain for the function, i.e. the number
// of bits to check
func ClientInitialize(numBits uint) *Fss {
	f := new(Fss)
	f.NumBits = numBits
	f.PrfKeys = make([][]byte, initPRFLen)
	// Create fixed AES blocks
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := uint(0); i < initPRFLen; i++ {
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
	f.M = 4 // Default is 4. Only used in multiparty. To change this, you should change the size of the CW in multiparty keys. Read comments there.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)
	return f
}

// This is based on the following paper:
// Boyle, Elette, Niv Gilboa, and Yuval Ishai. "Function Secret Sharing: Improvements and Extensions." Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2016.

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

// This function contains the 2-party FSS key generation for interval functions, i.e. <, > functions.
// The usage is similar to 2-party FSS for equality functions.

func (f Fss) GenerateTreeLt(a, b uint) []ServerKeyLt {
	k := make([]ServerKeyLt, 2)

	k[0].cw = make([][]CWLt, 2)
	k[0].cw[0] = make([]CWLt, f.NumBits)
	k[0].cw[1] = make([]CWLt, f.NumBits)
	k[1].cw = make([][]CWLt, 2)
	k[1].cw[0] = make([]CWLt, f.NumBits)
	k[1].cw[1] = make([]CWLt, f.NumBits)

	k[0].s = make([][]byte, 2)
	k[0].s[0] = make([]byte, aes.BlockSize)
	k[0].s[1] = make([]byte, aes.BlockSize)
	k[1].s = make([][]byte, 2)
	k[1].s[0] = make([]byte, aes.BlockSize)
	k[1].s[1] = make([]byte, aes.BlockSize)

	k[0].t = make([]uint8, 2)
	k[1].t = make([]uint8, 2)
	k[0].v = make([]uint, 2)
	k[1].v = make([]uint, 2)
	// Figure out first bit
	aBit := getBit(a, (f.N - f.NumBits + 1), f.N)
	naBit := aBit ^ 1

	// Initialize seeds (store as an array for each server)
	// The first AES_SIZE bits are for the 0 bit
	// The second AES_SIZE bits are for the 1 bit
	s0 := make([]byte, aes.BlockSize*2)
	s1 := make([]byte, aes.BlockSize*2)
	aStart := int(aes.BlockSize * aBit)
	naStart := int(aes.BlockSize * naBit)

	rand.Read(s0[aStart : aStart+aes.BlockSize])
	rand.Read(s1[aStart : aStart+aes.BlockSize])
	rand.Read(s0[naStart : naStart+aes.BlockSize])
	// Ensure the "not a" bits are the same
	copy(s1[naStart:naStart+aes.BlockSize], s0[naStart:naStart+aes.BlockSize])
	//fmt.Println("s0:", s0)
	//fmt.Println("s1:", s1)
	// Set initial "t" bits
	t0 := make([]uint8, 2)
	t1 := make([]uint8, 2)
	temp := make([]byte, 2)
	rand.Read(temp)

	// Make sure t0a and t1a are different
	t0[aBit] = uint8(temp[0]) % 2
	t1[aBit] = t0[aBit] ^ 1

	// Make sure t0na = t1na
	t0[naBit] = uint8(temp[1]) % 2
	t1[naBit] = t0[naBit]

	// Generate random Vs
	v0 := make([]uint, 2)
	v1 := make([]uint, 2)

	// make sure v0a + -v1a = 0
	v0[aBit] = randomCryptoInt()
	v1[aBit] = v0[aBit]

	// make sure v0na + -v1na = a1 * b
	v0[naBit] = randomCryptoInt()
	v1[naBit] = v0[naBit] - b*uint(aBit)

	// Store generated values into the key
	copy(k[0].s[0], s0[0:aes.BlockSize])
	copy(k[0].s[1], s0[aes.BlockSize:aes.BlockSize*2])
	copy(k[1].s[0], s1[0:aes.BlockSize])
	copy(k[1].s[1], s1[aes.BlockSize:aes.BlockSize*2])
	k[0].t[0] = t0[0]
	k[0].t[1] = t0[1]
	k[1].t[0] = t1[0]
	k[1].t[1] = t1[1]
	k[0].v[0] = v0[0]
	k[0].v[1] = v0[1]
	k[1].v[0] = v1[0]
	k[1].v[1] = v1[1]

	// Assign keys and start cipher
	key0 := make([]byte, aes.BlockSize)
	key1 := make([]byte, aes.BlockSize)
	copy(key0, s0[aStart:aStart+aes.BlockSize])
	copy(key1, s1[aStart:aStart+aes.BlockSize])
	tbit0, tbit1 := t0[aBit], t1[aBit]

	cs0 := make([]byte, aes.BlockSize*2)
	cs1 := make([]byte, aes.BlockSize*2)
	ct0 := make([]uint8, 2)
	ct1 := make([]uint8, 2)

	var cv [][]uint
	cv = make([][]uint, 2)
	cv[0] = make([]uint, 2)
	cv[1] = make([]uint, 2)

	for i := uint(0); i < f.NumBits-1; i++ {
		// Figure out next bit
		aBit = getBit(a, (f.N - f.NumBits + i + 2), f.N)
		naBit = aBit ^ 1

		prf(key0, f.FixedBlocks, 4, f.Temp, f.Out)
		copy(s0, f.Out[:aes.BlockSize*2])
		t0[0] = f.Out[aes.BlockSize*2] % 2
		t0[1] = f.Out[aes.BlockSize*2+1] % 2
		conv, _ := binary.Uvarint(f.Out[aes.BlockSize*2+8 : aes.BlockSize*2+16])
		v0[0] = uint(conv)
		conv, _ = binary.Uvarint(f.Out[aes.BlockSize*2+16 : aes.BlockSize*2+24])
		v0[1] = uint(conv)

		prf(key1, f.FixedBlocks, 4, f.Temp, f.Out)
		copy(s1, f.Out[:aes.BlockSize*2])
		t1[0] = f.Out[aes.BlockSize*2] % 2
		t1[1] = f.Out[aes.BlockSize*2+1] % 2
		conv, _ = binary.Uvarint(f.Out[aes.BlockSize*2+8 : aes.BlockSize*2+16])
		v1[0] = uint(conv)
		conv, _ = binary.Uvarint(f.Out[aes.BlockSize*2+16 : aes.BlockSize*2+24])
		v1[1] = uint(conv)

		//fmt.Println("s0:", s0)
		//fmt.Println("s1:", s1)
		// Redefine aStart and naStart based on new a's
		aStart = int(aes.BlockSize * aBit)
		naStart = int(aes.BlockSize * naBit)

		// Create cs and ct for next bit
		rand.Read(cs0[aStart : aStart+aes.BlockSize])
		rand.Read(cs1[aStart : aStart+aes.BlockSize])

		// Pick random cs0na and pick cs1na s.t.
		// cs0na xor cs1na xor s0na xor s1na = 0
		rand.Read(cs0[naStart : naStart+aes.BlockSize])

		for j := 0; j < aes.BlockSize; j++ {
			cs1[naStart+j] = s0[naStart+j] ^ s1[naStart+j] ^ cs0[naStart+j]
		}

		rand.Read(temp)
		// Set ct0a and ct1a s.t.
		// ct0a xor ct1a xor t0a xor t1a = 1
		ct0[aBit] = uint8(temp[0]) % 2
		ct1[aBit] = ct0[aBit] ^ t0[aBit] ^ t1[aBit] ^ 1

		// Set ct0na and ct1na s.t.
		// ct0na xor ct1na xor t0na xor t1na = 0
		ct0[naBit] = uint8(temp[1]) % 2
		ct1[naBit] = ct0[naBit] ^ t0[naBit] ^ t1[naBit]

		cv[tbit0][aBit] = randomCryptoInt()
		cv[tbit1][aBit] = v0[aBit] + cv[tbit0][aBit] - v1[aBit]

		cv[tbit0][naBit] = randomCryptoInt()
		cv[tbit1][naBit] = cv[tbit0][naBit] + v0[naBit] - v1[naBit] - b*uint(aBit)

		k[0].cw[0][i].cs = make([][]byte, 2)
		k[0].cw[0][i].cs[0] = make([]byte, aes.BlockSize)
		k[0].cw[0][i].cs[1] = make([]byte, aes.BlockSize)
		k[0].cw[1][i].cs = make([][]byte, 2)
		k[0].cw[1][i].cs[0] = make([]byte, aes.BlockSize)
		k[0].cw[1][i].cs[1] = make([]byte, aes.BlockSize)

		k[0].cw[0][i].ct = make([]uint8, 2)
		k[0].cw[0][i].cv = make([]uint, 2)
		k[0].cw[1][i].ct = make([]uint8, 2)
		k[0].cw[1][i].cv = make([]uint, 2)

		copy(k[0].cw[0][i].cs[0], cs0[0:aes.BlockSize])
		copy(k[0].cw[0][i].cs[1], cs0[aes.BlockSize:aes.BlockSize*2])
		k[0].cw[0][i].ct[0] = ct0[0]
		k[0].cw[0][i].ct[1] = ct0[1]
		copy(k[0].cw[1][i].cs[0], cs1[0:aes.BlockSize])
		copy(k[0].cw[1][i].cs[1], cs1[aes.BlockSize:aes.BlockSize*2])
		k[0].cw[1][i].ct[0] = ct1[0]
		k[0].cw[1][i].ct[1] = ct1[1]

		k[0].cw[0][i].cv[0] = cv[0][0]
		k[0].cw[0][i].cv[1] = cv[0][1]
		k[0].cw[1][i].cv[0] = cv[1][0]
		k[0].cw[1][i].cv[1] = cv[1][1]

		k[1].cw[0][i].cs = make([][]byte, 2)
		k[1].cw[0][i].cs[0] = make([]byte, aes.BlockSize)
		k[1].cw[0][i].cs[1] = make([]byte, aes.BlockSize)
		k[1].cw[1][i].cs = make([][]byte, 2)
		k[1].cw[1][i].cs[0] = make([]byte, aes.BlockSize)
		k[1].cw[1][i].cs[1] = make([]byte, aes.BlockSize)

		k[1].cw[0][i].ct = make([]uint8, 2)
		k[1].cw[0][i].cv = make([]uint, 2)
		k[1].cw[1][i].ct = make([]uint8, 2)
		k[1].cw[1][i].cv = make([]uint, 2)

		copy(k[1].cw[0][i].cs[0], cs0[0:aes.BlockSize])
		copy(k[1].cw[0][i].cs[1], cs0[aes.BlockSize:aes.BlockSize*2])
		k[1].cw[0][i].ct[0] = ct0[0]
		k[1].cw[0][i].ct[1] = ct0[1]
		copy(k[1].cw[1][i].cs[0], cs1[0:aes.BlockSize])
		copy(k[1].cw[1][i].cs[1], cs1[aes.BlockSize:aes.BlockSize*2])
		k[1].cw[1][i].ct[0] = ct1[0]
		k[1].cw[1][i].ct[1] = ct1[1]

		k[1].cw[0][i].cv[0] = cv[0][0]
		k[1].cw[0][i].cv[1] = cv[0][1]
		k[1].cw[1][i].cv[0] = cv[1][0]
		k[1].cw[1][i].cv[1] = cv[1][1]

		// Find correct cs and ct
		var cs, ct []byte

		// Set next seeds and ts
		if tbit0 == 1 {
			cs = cs1
			ct = ct1
		} else {
			cs = cs0
			ct = ct0
		}
		for j := 0; j < len(key0); j++ {
			key0[j] = s0[aStart+j] ^ cs[aStart+j]
		}
		tbit0 = t0[aBit] ^ ct[aBit]
		if tbit1 == 1 {
			cs = cs1
			ct = ct1
		} else {
			cs = cs0
			ct = ct0
		}

		for j := 0; j < len(key1); j++ {
			key1[j] = s1[aStart+j] ^ cs[aStart+j]
		}

		tbit1 = t1[aBit] ^ ct[aBit]
	}

	return k
}

// This function is for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

func (f Fss) GenerateTreeEqMP(a, b, num_p uint) []FssKeyEqMP {
	keys := make([]FssKeyEqMP, num_p)
	p2 := uint(math.Pow(2, float64(num_p-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(num_p-1)/2.0)))
	v := uint(math.Ceil(math.Pow(2, float64(f.NumBits)) / float64(mu)))

	delta := a & ((1 << (f.NumBits / 2)) - 1)
	gamma := (a & (((1 << (f.NumBits + 1) / 2) - 1) << f.NumBits / 2)) >> f.NumBits / 2
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
