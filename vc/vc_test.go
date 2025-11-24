package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sort"
	"testing"
)

// --------------------------
// Helper: populate dummy users with keys
// --------------------------
// Generates 'n' dummy users with random ElGamal keypairs and random dk values
func populateDummyUsersWithKeys(vc *VoteCollector, n int) {
	if vc.users == nil {
		vc.users = make(map[string]*User)
	}
	for i := 1; i <= n; i++ {
		userID := fmt.Sprintf("u%d", i)
		dk := make([]byte, 16)
		_, err := rand.Read(dk)
		if err != nil {
			panic(err)
		}

		// Generate a dummy ElGamal keypair
		_, pk, _ := ElGamal.KGen(&vc.PP)

		vc.users[userID] = &User{
			userID: userID,
			port:   i,
			ApkU:   pk, // dummy public key
			dkU:    dk, // dummy double key
		}
	}
}

// Simulates secret-sharing and ElGamal encryption for a voting group
func benchmarkFullSetupVotingGroup(vc *VoteCollector) {
	// --- Extract users ---
	userIDs := make([]string, 0, len(vc.users))
	for id := range vc.users {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs)

	// --- Build successor ring ---
	successors := make(map[string]string)
	for i := 0; i < len(userIDs); i++ {
		successors[userIDs[i]] = userIDs[(i+1)%len(userIDs)]
	}

	// --- Generate random ri and split into shares ---
	low := big.NewInt(50)
	high := big.NewInt(100)
	rangeVal := new(big.Int).Sub(high, low)

	randoms := make(map[string]*big.Int)
	distribute := make(map[string][]*big.Int)

	for _, user := range userIDs {
		r_i, _ := rand.Int(rand.Reader, rangeVal)
		r_i.Add(r_i, low)
		randoms[user] = r_i
		splits := ElGamal.SplitSecret(r_i, len(userIDs))
		distribute[user] = append(distribute[user], splits...)
	}

	// Assign each user the shares from all other users
	for i, receiverID := range userIDs {
		sharesForUser := make([]*big.Int, 0, len(userIDs))
		for _, ownerID := range userIDs {
			sharesForUser = append(sharesForUser, distribute[ownerID][i])
		}
		vc.shares[receiverID] = sharesForUser
	}
	vc.randoms = randoms

	// --- Simulate sending shares (compute ElGamal encryption only) ---
	for _, ownerID := range userIDs {
		receiver := vc.users[ownerID]
		shares := vc.shares[ownerID]
		kBytes := vc.K
		Klen := len(kBytes)
		N := 1
		if Klen > N {
			N = Klen
		}

		for idx := 0; idx < N; idx++ {
			var sVal *big.Int
			if idx < len(shares) {
				sVal = shares[idx]
			} else {
				sVal = big.NewInt(0)
			}

			var kVal *big.Int
			if idx < Klen && Klen > 0 {
				kVal = new(big.Int).SetInt64(int64(kBytes[idx]))
			} else {
				kVal = big.NewInt(0)
			}

			// --- Perform actual ElGamal encryption ---
			Kparam := vc.users[ownerID].dkU
			_, _, _ = ElGamal.AEnc(vc.APP, vc.PP, Kparam, receiver.ApkU, sVal, kVal)
		}
	}
}

// Generate a single vote ciphertext
func genVote(vc *VoteCollector) [2]*big.Int {
	// Generate 10 random shares for user u1
	shares := make([]*big.Int, 10)
	for i := 0; i < len(shares); i++ {
		sVal, _ := rand.Int(rand.Reader, big.NewInt(50))
		shares[i] = sVal
	}
	vc.shares["u1"] = shares

	// Generate user's random ri
	low := big.NewInt(50)
	high := big.NewInt(100)
	rangeVal := new(big.Int).Sub(high, low)
	ri, _ := rand.Int(rand.Reader, rangeVal)
	vc.randoms["u1"] = ri

	// Generate real candidate (1–15)
	candidateRand, _ := rand.Int(rand.Reader, big.NewInt(15))   // 0..14
	candidate := new(big.Int).Add(candidateRand, big.NewInt(1)) // 1..15

	// Generate fake vote (16–20)
	fakeRand, _ := rand.Int(rand.Reader, big.NewInt(5)) // 0..4
	vf := new(big.Int).Add(fakeRand, big.NewInt(16))    // 16..20

	// Compute blind vote using the decrypted shares
	bi := ElGamal.ComputeBlindVotes(int(candidate.Int64()), ri, shares, vc.PP, vc.APP)

	// Encrypt blind vote with fake candidate
	c0, c1, _ := ElGamal.AEnc(vc.APP, vc.PP, vc.K, vc.ApkVC, vf, bi)
	return [2]*big.Int{c0, c1}
}

// Generate dummy VoteCollector with parameters
func genVC() *VoteCollector {
	// ElGamal parameters
	P := new(big.Int)
	P.SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	Q := new(big.Int).Sub(P, big.NewInt(1))
	G := big.NewInt(5)
	pp := ElGamal.Params{P: P, Q: Q, G: G}

	// Anamorphic params
	L := 5000
	S := big.NewInt(int64(L))
	T := big.NewInt(int64(L))
	app := ElGamal.AParams{L: L, S: S, T: T}

	// Generate a dummy authority keypair
	skA, pkA, _ := ElGamal.KGen(&pp)
	K, Tmap, _ := ElGamal.AGen(app.L, pp, pkA)

	vc := &VoteCollector{
		ApkVC:   pkA,
		AskVC:   skA,
		K:       K,
		Tmap:    Tmap,
		PP:      pp,
		APP:     app,
		randoms: make(map[string]*big.Int),
		shares:  make(map[string][]*big.Int),
	}

	return vc
}

// Generate a vote vector of length n
func formVoteVector(n int) []*big.Int {
	votes := make([]*big.Int, n)
	// Generate real candidate (1–15)
	candidateRand, _ := rand.Int(rand.Reader, big.NewInt(15))   // 0..14
	candidate := new(big.Int).Add(candidateRand, big.NewInt(1)) // 1..15
	for i := 0; i < len(votes); i++ {
		votes[i] = candidate
	}

	return votes
}

// --------------------------
// Benchmarks
// --------------------------
func BenchmarkVCRegistration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RegisterVC() // assumes a function that registers the VC
	}
}

func BenchmarkSetupVotingGroupRealParams(b *testing.B) {
	// Setup ElGamal & anamorphic parameters
	P := new(big.Int)
	P.SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	Q := new(big.Int).Sub(P, big.NewInt(1))
	G := big.NewInt(5)
	pp := ElGamal.Params{P: P, Q: Q, G: G}

	L := 5000
	S := big.NewInt(int64(L))
	T := big.NewInt(int64(L))
	app := ElGamal.AParams{L: L, S: S, T: T}

	// Generate a dummy authority keypair
	skA, pkA, err := ElGamal.KGen(&pp)
	if err != nil {
		b.Fatalf("KGen (Authority) failed: %v", err)
	}
	_ = skA
	_ = pkA

	for i := 0; i < b.N; i++ {
		dk := make([]byte, 16)
		_, err := rand.Read(dk)
		if err != nil {
			panic(err)
		}

		vc := &VoteCollector{
			users:  make(map[string]*User),
			shares: make(map[string][]*big.Int),
			K:      dk,
			APP:    app,
			PP:     pp,
		}

		populateDummyUsersWithKeys(vc, 10) // simulate 10 users

		b.StartTimer()
		benchmarkFullSetupVotingGroup(vc)
		b.StopTimer()
	}
}

// Benchmark saving a vote
func BenchmarkVCSaveVote(b *testing.B) {
	vc := genVC()
	ct := genVote(vc)
	populateDummyUsersWithKeys(vc, 1)

	for i := 0; i < b.N; i++ {
		userID := "u1"
		vfi := ElGamal.Dec(&vc.PP, vc.AskVC, ct[0], ct[1])
		bi := ElGamal.ADec(vc.APP, vc.PP, vc.K, vc.Tmap, ct[0], ct[1])

		// Compute final vote
		total := big.NewInt(0)
		S := big.NewInt(int64(vc.APP.L))
		half := new(big.Int).Div(S, big.NewInt(2))

		b := new(big.Int).Set(bi)

		if b.Cmp(half) > 0 {
			b.Sub(b, S)
		}
		total.Add(total, b)
		sumShares := big.NewInt(0)
		for _, s := range vc.shares[userID] {
			sumShares.Add(sumShares, s)
		}

		total = total.Sub(total, vc.randoms[userID])
		vote := total.Add(total, sumShares)
		vc.Votes = append(vc.Votes, vote)

		// Re-encrypt vote for storage
		pk := vc.users[userID].ApkU
		K := vc.users[userID].dkU
		ElGamal.AEnc(vc.APP, vc.PP, K, pk, vfi, vote)
		log.Printf("[VC] Received re-encrypted vote for user %s", userID)
	}
}

// Benchmark vote counting
func BenchmarkCountVotes(b *testing.B) {
	n := 10
	votes := formVoteVector(n)
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(serverURL + "/candidates")
		if err != nil {
			fmt.Println("Failed to fetch candidates:", err)
			return
		}
		var candidates []string
		json.NewDecoder(resp.Body).Decode(&candidates)
		resp.Body.Close()

		// Count votes per candidate
		voteCounts := make([]int, len(candidates))
		for _, v := range votes {
			if v == nil {
				continue
			}

			voteInt := int(v.Int64())
			index := voteInt - 1

			if index >= 0 && index < len(candidates) {
				voteCounts[index]++
			} else {
				fmt.Println("Invalid vote value: ", v.String())
			}
		}

		// Print vote counts
		for i, candidate := range candidates {
			fmt.Printf("Candidate %s got %d votes\n", candidate, voteCounts[i])

		}
	}
}
