package ElGamal

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// encodeVote: candidate is 1-based index, returns base^(candidate-1)
func EncodeVote(candidate int, base int64) *big.Int {
	if candidate <= 0 {
		return big.NewInt(0)
	}
	b := big.NewInt(base)
	exp := new(big.Int).Exp(b, big.NewInt(int64(candidate-1)), nil)
	return exp
}

// decodeCounts: extract number of votes for each candidate using given base
func DecodeCounts(total *big.Int, numCandidates int, base int64) []*big.Int {
	counts := make([]*big.Int, numCandidates)
	tmp := new(big.Int).Set(total)
	b := big.NewInt(base)
	for i := 0; i < numCandidates; i++ {
		counts[i] = new(big.Int).Mod(tmp, b)
		tmp.Div(tmp, b)
	}
	return counts
}

// Splits a secret r into n additive shares for secure distribution.
func SplitSecret(r *big.Int, n int) []*big.Int {
	parts := make([]*big.Int, n)
	remaining := new(big.Int).Set(r)
	for i := 0; i < n-1; i++ {
		bound := new(big.Int).Add(remaining, big.NewInt(1))
		x, _ := rand.Int(rand.Reader, bound)
		parts[i] = new(big.Int).Set(x)
		remaining.Sub(remaining, x)
	}
	parts[n-1] = new(big.Int).Set(remaining) // last share ensures sum equals r
	return parts
}

// Computes the blinded vote for a user.
func ComputeBlindVotes(vi int, r *big.Int, base int64, shares []*big.Int, pp Params, app AParams) *big.Int {
	// encode candidate as base^(vi-1)
	v_i := EncodeVote(vi, base)

	// sum all secret shares
	sumShares := big.NewInt(0)
	for _, s := range shares {
		sumShares.Add(sumShares, s)
	}

	// blinded vote: (v_i + r_i - sumShares) mod L
	bi := new(big.Int).Add(v_i, r)
	bi.Sub(bi, sumShares)
	bi.Mod(bi, big.NewInt(int64(app.L))) // modulo L to keep in range
	return bi
}

// Decrypts all votes and sums them into a total.
func TallyVotes(app AParams, pp Params, K []byte, Tmap map[string]*big.Int, votes [][2]*big.Int) *big.Int {
	total := big.NewInt(0)
	S := big.NewInt(int64(app.L))
	half := new(big.Int).Div(S, big.NewInt(2))
	for _, vote := range votes {
		// decrypt vote
		bi := ADec(app, pp, K, Tmap, vote[0], vote[1])
		if bi == nil {
			continue
		}
		b := new(big.Int).Set(bi)

		// convert to signed representation in range [-L/2, L/2)
		if b.Cmp(half) > 0 {
			b.Sub(b, S)
		}

		// accumulate total
		total.Add(total, b)
	}
	// ensure total in [0, S) for digit extraction
	total.Mod(total, S)
	return total
}

// Decodes total votes and identifies the candidate with most votes
func DetermineWinner(total *big.Int, base int64, numCandidates int) int {
	counts := DecodeCounts(total, numCandidates, base)

	// print counts for transparency
	fmt.Println("\nDecoded candidate vote counts:")
	for i, c := range counts {
		fmt.Printf("Candidate %2d: %s votes\n", i+1, c.String())
	}

	// find candidate with max votes
	maxIdx := 0
	for i := 1; i < numCandidates; i++ {
		if counts[i].Cmp(counts[maxIdx]) > 0 {
			maxIdx = i
		}
	}
	return maxIdx + 1 // convert 0-based index to 1-based candidate ID
}
