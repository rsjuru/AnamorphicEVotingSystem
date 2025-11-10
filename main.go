package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"crypto/rand"
	"fmt"
	"math/big"
)

// Represents a voter with their keys, random value, and shares
type User struct {
	userID string              // unique identifier
	ask    *big.Int            // private key
	apk    *big.Int            // public key
	K      []byte              // auxiliary key for anamorphic encryption
	Tmap   map[string]*big.Int // map for anamorphic encryption
	r      *big.Int            // random value for blinding
	Shares []*big.Int          // secret shares from other users
}

// Represents the vote collector that collects the votes
type VC struct {
	Ask   *big.Int            // private key of VC
	Apk   *big.Int            // public key of VC
	K     []byte              // key for anamorphic encryption
	Tmap  map[string]*big.Int // map for anamorphic encryption
	Votes [][2]*big.Int       // encrypted votes (c0, c1)
}

// Map of users by ID
var users = make(map[string]*User)

// Creates a given number of users with ElGamal key pairs
func GenerateUsers(pp ElGamal.Params, L int, number int) {
	for i := 0; i < number; i++ {
		id := fmt.Sprintf("user%d", i+1)
		sk, pk, _ := ElGamal.KGen(&pp)        // generate ElGamal key pair
		K, Tmap, _ := ElGamal.AGen(L, pp, pk) // generate double key for anamorphic encryption
		user := User{userID: id, ask: sk, apk: pk, K: K, Tmap: Tmap}
		users[id] = &user
	}
}

// Generates a random r_i for each user in [low, high)
// and splits it into secret shares distributed to all users.
func DistributeShares(low, high *big.Int) {
	n := len(users)
	userList := make([]string, 0, n)
	for id := range users {
		userList = append(userList, id)
	}

	for _, senderID := range userList {
		// generate r_i randomly in [low, high)
		rangeVal := new(big.Int).Sub(high, low)
		r_i, _ := rand.Int(rand.Reader, rangeVal)
		r_i.Add(r_i, low)
		users[senderID].r = new(big.Int).Set(r_i)

		// split r_i into n shares and distribute to all users
		shares := ElGamal.SplitSecret(r_i, n)
		for i, receiverID := range userList {
			receiver := users[receiverID]
			receiver.Shares = append(receiver.Shares, new(big.Int).Set(shares[i]))
		}
	}
}

// ---------- Main ----------
func main() {
	// ElGamal system parameters
	P := new(big.Int)
	P.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)
	Q := new(big.Int).Sub(P, big.NewInt(1))
	G := big.NewInt(5)
	pp := ElGamal.Params{P: P, Q: Q, G: G}

	// VC key generation
	skA, pkA, _ := ElGamal.KGen(&pp)
	Lval := int64(100000)
	S := big.NewInt(Lval)
	T := big.NewInt(Lval)
	app := ElGamal.AParams{L: int(Lval), S: S, T: T}
	K, Tmap, _ := ElGamal.AGen(int(Lval), pp, pkA)
	vc := VC{Ask: skA, Apk: pkA, K: K, Tmap: Tmap}

	// --- Users & election setup ---
	numUsers := 5
	numCandidates := 8
	base := int64(numUsers + 1) // base used to encode votes = numUsers + 1

	// generate users with keys
	GenerateUsers(pp, int(Lval), numUsers)

	// generate and distribute secret shares
	low := big.NewInt(5000)
	high := big.NewInt(10000)
	DistributeShares(low, high)

	// --- Voting phase --
	userList := make([]string, 0, len(users))
	for id := range users {
		userList = append(userList, id)
	}

	for _, ID := range userList {
		// select candidate randomly (1...6)
		randIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(6)))
		candidate := int(randIdx.Int64()) + 1
		fmt.Println("Vote: ", candidate)

		// fake vote for evil candidate
		vf := big.NewInt(7)

		// compute blinded vote: v_i = base^(candidate-1), then apply blinding r - sum(shares)
		bi := ElGamal.ComputeBlindVotes(candidate, users[ID].r, base, users[ID].Shares, pp, app)

		// encrypt the blided vote and store in VC
		c0, c1, _ := ElGamal.AEnc(app, pp, vc.K, vc.Apk, vf, bi)
		vc.Votes = append(vc.Votes, [2]*big.Int{c0, c1})
	}

	// --- Tallying phase ---
	total := ElGamal.TallyVotes(app, pp, K, Tmap, vc.Votes)

	// decode counts and determine winner
	winner := ElGamal.DetermineWinner(total, base, numCandidates)
	fmt.Println("\n🏆 The winner of the election is candidate:", winner)
}
