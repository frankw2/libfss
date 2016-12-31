package libfss

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"time"
)

type CWLt struct {
	cs [2][]byte
	ct [2]uint8
	cv [2]uint
}

type ServerKeyLt struct {
	s  [2][]byte
	t  [2]uint8
	v  [2]uint
	cw [2][]CWLt // Should be length n
}

func (f Fss) generateTreeLt(a, b uint) []ServerKeyLt {
	k := make([]ServerKeyLt, 2)

	k[0].cw[0] = make([]CWLt, f.NumBits)
	k[0].cw[1] = make([]CWLt, f.NumBits)
	k[1].cw[0] = make([]CWLt, f.NumBits)
	k[1].cw[1] = make([]CWLt, f.NumBits)

	k[0].s[0] = make([]byte, aes.BlockSize)
	k[0].s[1] = make([]byte, aes.BlockSize)
	k[1].s[0] = make([]byte, aes.BlockSize)
	k[1].s[1] = make([]byte, aes.BlockSize)

	// Figure out first bit
	aBit := getBit(a, (f.N - f.NumBits + 1), f.N)
	naBit := aBit ^ 1

	// Initialize seeds (store as an array for each server)
	// The first AES_SIZE bits are for the 0 bit
	// The second AES_SIZE bits are for the 1 bit
	s0 := make([]byte, aes.BlockSize*2)
	s1 := make([]byte, aes.BlockSize*2)
	aStart := int(AES_SIZE * aBit)
	naStart := int(AES_SIZE * naBit)

	rand.Read(s0[aStart : aStart+aes.BlockSize])
	rand.Read(s1[aStart : aStart+aes.BlockSize])
	rand.Read(s0[naStart : naStart+aes.BlockSize])
	// Ensure the "not a" bits are the same
	copy(s1[naStart:naStart+aes.BlockSize], s0[naStart:naStart+aes.BlockSize])

	// Set initial "t" bits
	t0 := make([]uint8, 2)
	t1 := make([]uint8, 2)
	temp := make([]byte, 2)
	_, err = rand.Read(temp)
	if err != nil {
		panic(err)
	}
	// Make sure t0a and t1a are different
	t0[aBit] = uint8(temp[0]) % 2
	t1[aBit] = (t0[aBit] + 1) % 2

	// Make sure t0na = t1na
	t0[naBit] = uint8(temp[1]) % 2
	t1[naBit] = t0[naBit]

	// Generate random Vs
	v0 := make([]uint, 2)
	v1 := make([]uint, 2)

	// make sure v0a + -v1a = 0
	v0[aBit], err = uint(rand.Int())
	if err != nil {
		panic(err)
	}
	v1[aBit] = -v0[aBit]

	// make sure v0na + -v1na = a1 * b
	v0[naBit], err = uint(rand.Int())
	if err != nil {
		panic(err)
	}
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
	key0, key1 := s0[aStart:aStart+aes.BlockSize], s1[aStart:aStart+aes.BlockSize]
	tbit0, tbit1 := t0[aBit], t1[aBit]

	s0 = make([]byte, aes.BlockSize*2)
	s1 = make([]byte, aes.BlockSize*2)
	temp0 := make([]byte, aes.BlockSize)
	temp1 := make([]byte, aes.BlockSize)
	t0 = make([]uint8, 2)
	t1 = make([]uint8, 2)

	// Byte arrays for random Vs
	vall0 := make([]byte, aes.BlockSize)
	vall1 := make([]byte, aes.BlockSize)

	cs0 := make([]byte, aes.BlockSize*2)
	cs1 := make([]byte, aes.BlockSize*2)
	ct0 := make([]uint8, 2)
	ct1 := make([]uint8, 2)

	var cv [2][]uint
	cv[0] = make([]uint, 2)
	cv[1] = make([]uint, 2)

	for i := 0; i < f.N-1; i++ {
		// Figure out next bit
		aBit = getBit(a, (f.N - f.NumBits + i + 2), f.N)
		naBit = aBit ^ 1

		// TODO: START FIXING HERE!!!!

		// Implement AES CTR because the library is too slow
		block0.Encrypt(s0[0:AES_SIZE], pt0)
		block0.Encrypt(s0[AES_SIZE:AES_SIZE*2], pt1)
		block0.Encrypt(temp0, pt2)
		block0.Encrypt(vall0, pt3)

		block1.Encrypt(s1[0:AES_SIZE], pt0)
		block1.Encrypt(s1[AES_SIZE:AES_SIZE*2], pt1)
		block1.Encrypt(temp1, pt2)
		block1.Encrypt(vall1, pt3)

		for j := 0; j < AES_SIZE; j++ {
			s0[j] = s0[j] ^ pt0[j]
			s0[AES_SIZE+j] = s0[AES_SIZE+j] ^ pt1[j]
			temp0[j] = temp0[j] ^ pt2[j]
			vall0[j] = vall0[j] ^ pt3[j]
			s1[j] = s1[j] ^ pt0[j]
			s1[AES_SIZE+j] = s1[AES_SIZE+j] ^ pt1[j]
			temp1[j] = temp1[j] ^ pt2[j]
			vall1[j] = vall1[j] ^ pt3[j]
		}
		t0[0] = uint8(temp0[0]) % 2
		t0[1] = uint8(temp0[1]) % 2
		t1[0] = uint8(temp1[0]) % 2
		t1[1] = uint8(temp1[1]) % 2

		v0[0] = new(big.Int).SetBytes(vall0[0 : N/8])
		v0[1] = new(big.Int).SetBytes(vall0[N/8 : N/4])
		v1[0] = new(big.Int).SetBytes(vall1[0 : N/8])
		v1[1] = new(big.Int).SetBytes(vall1[N/8 : N/4])

		// Redefine aStart and naStart based on new a's
		aStart = int(AES_SIZE * a)
		naStart = int(AES_SIZE * na)

		// Create cs and ct for next bit
		_, err = rand.Read(cs0[aStart : aStart+AES_SIZE])
		if err != nil {
			panic(err)
		}
		_, err = rand.Read(cs1[aStart : aStart+AES_SIZE])
		if err != nil {
			panic(err)
		}

		// Pick random cs0na and pick cs1na s.t.
		// cs0na xor cs1na xor s0na xor s1na = 0
		_, err = rand.Read(cs0[naStart : naStart+AES_SIZE])
		if err != nil {
			panic(err)
		}

		for j := 0; j < AES_SIZE; j++ {
			cs1[naStart+j] = s0[naStart+j] ^ s1[naStart+j] ^ cs0[naStart+j]
		}

		_, err = rand.Read(temp)
		if err != nil {
			panic(err)
		}
		// Set ct0a and ct1a s.t.
		// ct0a xor ct1a xor t0a xor t1a = 1
		ct0[a] = uint8(temp[0]) % 2
		ct1[a] = ct0[a] ^ t0[a] ^ t1[a] ^ 1

		// Set ct0na and ct1na s.t.
		// ct0na xor ct1na xor t0na xor t1na = 0
		ct0[na] = uint8(temp[1]) % 2
		ct1[na] = ct0[na] ^ t0[na] ^ t1[na]

		cv[tbit0][a], err = rand.Int(rand.Reader, prime)
		if err != nil {
			panic(err)
		}

		cv[tbit1][a] = new(big.Int)
		cv[tbit1][a].Add(cv[tbit0][a], v0[a])
		cv[tbit1][a].Sub(cv[tbit1][a], v1[a])
		cv[tbit1][a].Mod(cv[tbit1][a], prime)

		cv[tbit0][na], err = rand.Int(rand.Reader, prime)
		if err != nil {
			panic(err)
		}

		cv[tbit1][na] = new(big.Int)
		cv[tbit1][na].Add(cv[tbit0][na], v0[na])
		cv[tbit1][na].Sub(cv[tbit1][na], v1[na])
		cv[tbit1][na].Sub(cv[tbit1][na], new(big.Int).SetUint64(b_input*uint64(a)))
		cv[tbit1][na].Mod(cv[tbit1][na], prime)

		k0.cw[0][i].cs[0] = make([]byte, AES_SIZE)
		k0.cw[0][i].cs[1] = make([]byte, AES_SIZE)
		k0.cw[1][i].cs[0] = make([]byte, AES_SIZE)
		k0.cw[1][i].cs[1] = make([]byte, AES_SIZE)

		copy(k0.cw[0][i].cs[0], cs0[0:AES_SIZE])
		copy(k0.cw[0][i].cs[1], cs0[AES_SIZE:AES_SIZE*2])
		k0.cw[0][i].ct[0] = ct0[0]
		k0.cw[0][i].ct[1] = ct0[1]
		copy(k0.cw[1][i].cs[0], cs1[0:AES_SIZE])
		copy(k0.cw[1][i].cs[1], cs1[AES_SIZE:AES_SIZE*2])
		k0.cw[1][i].ct[0] = ct1[0]
		k0.cw[1][i].ct[1] = ct1[1]

		k0.cw[0][i].cv[0] = cv[0][0]
		k0.cw[0][i].cv[1] = cv[0][1]
		k0.cw[1][i].cv[0] = cv[1][0]
		k0.cw[1][i].cv[1] = cv[1][1]

		k1.cw[0][i].cs[0] = make([]byte, AES_SIZE)
		k1.cw[0][i].cs[1] = make([]byte, AES_SIZE)
		k1.cw[1][i].cs[0] = make([]byte, AES_SIZE)
		k1.cw[1][i].cs[1] = make([]byte, AES_SIZE)

		copy(k1.cw[0][i].cs[0], cs0[0:AES_SIZE])
		copy(k1.cw[0][i].cs[1], cs0[AES_SIZE:AES_SIZE*2])
		k1.cw[0][i].ct[0] = ct0[0]
		k1.cw[0][i].ct[1] = ct0[1]
		copy(k1.cw[1][i].cs[0], cs1[0:AES_SIZE])
		copy(k1.cw[1][i].cs[1], cs1[AES_SIZE:AES_SIZE*2])
		k1.cw[1][i].ct[0] = ct1[0]
		k1.cw[1][i].ct[1] = ct1[1]

		k1.cw[0][i].cv[0] = cv[0][0]
		k1.cw[0][i].cv[1] = cv[0][1]
		k1.cw[1][i].cv[0] = cv[1][0]
		k1.cw[1][i].cv[1] = cv[1][1]

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
		tbit0 = t0[a] ^ ct[a]
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

		tbit1 = t1[a] ^ ct[a]
	}

	return k0, k1
}

func evaluateLt(k *ServerKeyLt, x uint64) uint {
	xi := getBit(x, 1)
	s := k.s[xi]
	t := k.t[xi]
	v := new(big.Int).Set(k.v[xi])

	// Use these plaintexts to get values from PRF
	sArray := make([]byte, AES_SIZE*2)
	temp := make([]uint8, AES_SIZE)

	vByte := make([]byte, AES_SIZE)
	for i := 1; i < N; i++ {
		// Get current bit
		xi = getBit(x, uint(i+1))

		block, err := aes.NewCipher(s)
		if err != nil {
			panic(err)
		}

		block.Encrypt(sArray[0:AES_SIZE], pt0)
		block.Encrypt(sArray[AES_SIZE:AES_SIZE*2], pt1)
		block.Encrypt(temp, pt2)
		block.Encrypt(vByte, pt3)

		for j := 0; j < AES_SIZE; j++ {
			sArray[j] = sArray[j] ^ pt0[j]
			sArray[AES_SIZE+j] = sArray[AES_SIZE+j] ^ pt1[j]
			temp[j] = temp[j] ^ pt2[j]
			vByte[j] = vByte[j] ^ pt3[j]
		}
		// Pick the right values to use based on bit of x
		xStart := int(AES_SIZE * xi)
		s = sArray[xStart : xStart+AES_SIZE]
		for j := 0; j < AES_SIZE; j++ {
			s[j] = s[j] ^ k.cw[t][i-1].cs[xi][j]
		}
		vStart := int(N / 8 * xi)
		v.Add(v, new(big.Int).SetBytes(vByte[vStart:vStart+N/8]))
		v.Add(v, k.cw[t][i-1].cv[xi])
		v.Mod(v, prime)
		t = (uint8(temp[xi]) % 2) ^ k.cw[t][i-1].ct[xi]

	}

	return v
}
