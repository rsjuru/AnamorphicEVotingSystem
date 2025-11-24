package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"crypto/rand"
	"log"
	"math/big"
	"strconv"
	"testing"
)

// ------------ Helper Functions ------------ //

// Creates a fully initialized User object
func genUser() (*User, *big.Int, []byte) {
	// Large safe prime (1536-bit MODP Group)
	P := new(big.Int)
	P.SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	Q := new(big.Int).Sub(P, big.NewInt(1)) // subgroup order P-1
	G := big.NewInt(5)                      // generator
	pp := ElGamal.Params{P: P, Q: Q, G: G}

	// 2️⃣ Authority Anamorphic params
	L := 5000
	S := big.NewInt(int64(L))
	T := big.NewInt(int64(L))
	app := ElGamal.AParams{L: L, S: S, T: T}

	// ElGamal key pair for user
	sk, pk, _ := ElGamal.KGen(&pp)

	// Anamorphic secret K and Tmap
	K, Tmap, _ := ElGamal.AGen(app.L, pp, pk)

	// Construct full user object
	user := &User{
		UserID: "u1",
		Apk:    pk,
		Ask:    sk,
		Tmap:   Tmap,
		K:      K,
		PP:     pp,
		APP:    app,
	}

	// Keys for verification ciphertexts (VC)
	_, pkVC, _ := ElGamal.KGen(&pp)
	KVC, _, _ := ElGamal.AGen(app.L, pp, pkVC)

	// Random real vote (1-15)
	candidateRand, _ := rand.Int(rand.Reader, big.NewInt(15))   // 0..14
	candidate := new(big.Int).Add(candidateRand, big.NewInt(1)) // 1..15

	// Random fake vote (16-20)
	fakeRand, _ := rand.Int(rand.Reader, big.NewInt(5)) // 0..4
	vf := new(big.Int).Add(fakeRand, big.NewInt(16))    // 16..20

	user.vf = vf
	user.vi = candidate

	return user, pkVC, KVC
}

// Creates ElGamal anamorphic ciphertexts for each byte of K.
func generateCiphertexts(K []byte, user *User) [2][]*big.Int {
	_, err := rand.Read(K)
	if err != nil {
		panic(err)
	}
	shares := make([]*big.Int, 10)

	c0s := make([]*big.Int, 0)
	c1s := make([]*big.Int, 0)
	Klen := len(K)

	for i := 0; i < Klen; i++ {
		// random small share for first 10 entries, else 0
		var sVal *big.Int
		if i < len(shares) {
			sVal, _ = rand.Int(rand.Reader, big.NewInt(50))
		} else {
			sVal = big.NewInt(0)
		}

		// kVal corresponds to byte value K[i]
		var kVal *big.Int
		if i < Klen && Klen > 0 {
			kVal = new(big.Int).SetInt64(int64(K[i]))
		} else {
			kVal = big.NewInt(0)
		}

		c0, c1, _ := ElGamal.AEnc(user.APP, user.PP, user.K, user.Apk, sVal, kVal)
		c0s = append(c0s, c0)
		c1s = append(c1s, c1)
	}

	return [2][]*big.Int{c0s, c1s}
}

// Generates confirmation ciphertexts (fake vote, real vote)
func genConf(user *User) [2]*big.Int {
	c0, c1, _ := ElGamal.AEnc(user.APP, user.PP, user.K, user.Apk, user.vf, user.vi)
	return [2]*big.Int{c0, c1}
}

// Measures performance of user registration
func BenchmarkUserReg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		userID := strconv.Itoa(i)
		RegisterUser(userID)
	}
}

/*
BenchmarkUserVote simulates:

1. Receiving ciphertexts from server
2. Decrypting shares and anamorphic bytes
3. Reconstructing K
4. Generating real/fake votes again
5. Computing blind vote
6. Re-encrypting a vote using VC keys

It measures full voter-side cost.
*/
func BenchmarkUserVote(b *testing.B) {

	// Example range for randomization
	low := big.NewInt(50)
	high := big.NewInt(100)
	rangeVal := new(big.Int).Sub(high, low)

	ri, _ := rand.Int(rand.Reader, rangeVal)

	user, pkVC, K := genUser()
	user.ApkVC = pkVC

	// Pre-generated ciphertexts from authority
	ct := generateCiphertexts(K, user)

	for i := 0; i < b.N; i++ {
		c0s := ct[0]
		c1s := ct[1]

		shares := make([]*big.Int, 0)
		kvals := make([]*big.Int, 0)

		// Decrypt shares (si) and anamorphic bytes (ki)
		for i := 0; i < len(c0s); i++ {
			c0 := c0s[i]
			c1 := c1s[i]

			si := ElGamal.Dec(&user.PP, user.Ask, c0, c1)
			ki := ElGamal.ADec(user.APP, user.PP, user.K, user.Tmap, c0, c1)

			shares = append(shares, si)
			kvals = append(kvals, ki)

		}

		// remove padded zeros
		cleanShares := make([]*big.Int, 0)
		for _, s := range shares {
			if s.Sign() != 0 { // ignore padded zeros
				cleanShares = append(cleanShares, s)
			}
		}

		// Reassamble K bytes
		kBytes := make([]byte, 0)
		for _, kv := range kvals {
			kBytes = append(kBytes, byte(kv.Int64()))
		}
		user.dkVC = kBytes

		// generate new fake/real vote pair
		candidateRand, _ := rand.Int(rand.Reader, big.NewInt(15))   // 0..14
		candidate := new(big.Int).Add(candidateRand, big.NewInt(1)) // 1..15

		fakeRand, _ := rand.Int(rand.Reader, big.NewInt(5)) // 0..4
		vf := new(big.Int).Add(fakeRand, big.NewInt(16))    // 16..20

		user.vf = vf
		user.vi = candidate

		// Compute blind vote using the decrypted shares
		bi := ElGamal.ComputeBlindVotes(int(candidate.Int64()), ri, cleanShares, user.PP, user.APP)

		// FInal encryption using vote collector's key
		ElGamal.AEnc(user.APP, user.PP, user.dkVC, user.ApkVC, vf, bi)
	}
}

/*
BenchmarkUserConfirm - decrypts the "confirmation ciphertext"
and checks if the vote was correctly stored (fake + real vote match).
*/
func BenchmarkUserConfirm(b *testing.B) {
	user, _, _ := genUser()
	ctconf := genConf(user)
	c0conf, c1conf := ctconf[0], ctconf[1]

	for i := 0; i < b.N; i++ {
		vf := ElGamal.Dec(&user.PP, user.Ask, c0conf, c1conf)
		bi := ElGamal.ADec(user.APP, user.PP, user.K, user.Tmap, c0conf, c1conf)
		if user.vf.Cmp(vf) == 0 && user.vi.Cmp(bi) == 0 {
			log.Println("Vote saved correctly!")
		} else {
			log.Println("Failed confirmation!")
		}
	}
}
