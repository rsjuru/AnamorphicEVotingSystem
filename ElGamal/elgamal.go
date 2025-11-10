package ElGamal

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Returns a uniformly random integer n in [0, max)
func mustRandInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max) // draw n <- R {0, ..., max-1}
	if err != nil {
		panic(err) // abort immediately if randomness fails
	}
	return n // return the random integer
}

// (a*b) mod m
func modMul(a, b, m *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), m)
}

// a^e mod m
func modExp(a, e, m *big.Int) *big.Int {
	return new(big.Int).Exp(a, e, m)
}

// Wrapper using p (group modulus)
func modInverse(a, p *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, p)
}

// Generates a secret key sk ∈ [1, q-1] and pk = g^sk mod p
func KGen(pp *Params) (sk, pk *big.Int, err error) {
	// Generate random secret key sk in [1, q-1]
	sk, err = rand.Int(rand.Reader, pp.Q)
	if err != nil {
		return nil, nil, err
	}
	if sk.Sign() == 0 {
		sk = big.NewInt(1)
	}

	// pk = g^sk mod p
	pk = new(big.Int).Exp(pp.G, sk, pp.P)
	return sk, pk, nil
}

// Encrypts message m under public key pk with random r ∈ [1, q-1]
// Returns ciphertext (c0, c1, r)
func Enc(p, q, g, pk, msg *big.Int) (c0, c1, r *big.Int, err error) {
	// Random r in [1, q-1]
	r, err = rand.Int(rand.Reader, q)
	if err != nil {
		return nil, nil, nil, err
	}
	if r.Sign() == 0 {
		r = big.NewInt(1)
	}

	// c0 = (msg * pk^r) mod p
	pkR := new(big.Int).Exp(pk, r, p)
	c0 = new(big.Int).Mul(msg, pkR)
	c0.Mod(c0, p)

	// c1 = g^r mod p
	c1 = new(big.Int).Exp(g, r, p)

	return c1, c0, r, nil
}

// Decrypts ciphertext (c0, c1) with secret key sk
// Returns plaintext m = c0 * c1^(-sk) mod p
func Dec(pp *Params, sk, c0, c1 *big.Int) *big.Int {
	// Compute c1^(-sk) mod p
	// exp := new(big.Int).Neg(sk)
	// mul := new(big.Int).Exp(c1, exp, p)

	// safer: compute inverse explicitly
	inv := new(big.Int).Exp(c1, sk, pp.P)
	inv.ModInverse(inv, pp.P)

	m := new(big.Int).Mul(c0, inv)
	m.Mod(m, pp.P)

	return m
}

type Params struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

type AParams struct {
	L int
	S *big.Int
	T *big.Int
}

// ----------------- F function (AES based) -----------------
// x, y are small integers, pp.P is modulus
func F(pp Params, K []byte, x, y *big.Int) *big.Int {
	plaintext := make([]byte, 16)
	binary.LittleEndian.PutUint64(plaintext[0:8], x.Uint64())
	binary.LittleEndian.PutUint64(plaintext[8:16], y.Uint64())

	block, err := aes.NewCipher(K)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, 16)
	block.Encrypt(ciphertext, plaintext)

	// Convert AES output to little-endian integer to match Python's int.from_bytes(..., "little")
	rev := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		rev[i] = ciphertext[len(ciphertext)-1-i]
	}

	val := new(big.Int).SetBytes(rev)
	return new(big.Int).Mod(val, pp.P)
}

// ----------------- d function -----------------
func d(t, x *big.Int) *big.Int {
	return new(big.Int).Mod(x, t)
}

func xorBytes(a, b []byte) []byte {
	// Pad shorter slice with leading zeros
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)
	copy(aPadded[maxLen-len(a):], a)
	copy(bPadded[maxLen-len(b):], b)

	out := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		out[i] = aPadded[i] ^ bPadded[i]
	}
	return out
}

// ----------------- Anamorphic Key Generation -----------------
func AGen(l int, pp Params, pk *big.Int) ([]byte, map[string]*big.Int, *big.Int) {
	K := make([]byte, 16)
	_, err := rand.Read(K)
	if err != nil {
		panic(err)
	}

	T := make(map[string]*big.Int)
	for i := 0; i < l; i++ {
		val := modExp(pp.G, big.NewInt(int64(i)), pp.P)
		T[val.String()] = big.NewInt(int64(i))
	}

	return K, T, pk
}

// ----------------- Anamorphic Encryption (Python-equivalent) -----------------
func AEnc(app AParams, pp Params, K []byte, pk, msg, cm *big.Int) (*big.Int, *big.Int, *big.Int) {
	var r, c0, c1 *big.Int

	for {
		// 1. Choose random x ∈ [0, s−1] and y ∈ [0, t−1]
		x := mustRandInt(app.S)
		y := mustRandInt(app.T)

		// 2. Compute t := F(K, (x, y))
		tVal := F(pp, K, x, y)

		// 3. r := (cm + tVal) mod q     ← matches Python exactly
		r = new(big.Int).Add(cm, tVal)
		r.Mod(r, pp.Q) // NOTE: mod q (not p)

		// 4. until d(g^r) == y
		yCheck := new(big.Int).Mod(modExp(pp.G, r, pp.P), app.T)
		if yCheck.Cmp(y) == 0 {
			// 5. Compute ciphertext
			c0 = modMul(msg, modExp(pk, r, pp.P), pp.P)
			c1 = modExp(pp.G, r, pp.P)
			break
		}
	}

	// 6. Return ciphertext and r (for debugging if needed)
	return c0, c1, r
}

// ----------------- Anamorphic Decryption -----------------
func ADec(app AParams, pp Params, K []byte, T map[string]*big.Int, c0, c1 *big.Int) *big.Int {
	y := new(big.Int).Mod(c1, app.T)
	for x := big.NewInt(0); x.Cmp(app.S) < 0; x.Add(x, big.NewInt(1)) {
		tVal := F(pp, K, x, y)
		invG := modInverse(modExp(pp.G, tVal, pp.P), pp.P)
		if invG == nil {
			continue
		}
		sVal := modMul(c1, invG, pp.P)
		if val, ok := T[sVal.String()]; ok {
			return val
		}
	}
	return nil
}
