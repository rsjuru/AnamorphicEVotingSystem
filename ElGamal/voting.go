package ElGamal

import (
	"crypto/rand"
	"math/big"
)

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
func ComputeBlindVotes(vi int, r *big.Int, shares []*big.Int, pp Params, app AParams) *big.Int {
	// sum all secret shares
	sumShares := big.NewInt(0)
	for _, s := range shares {
		sumShares.Add(sumShares, s)
	}

	v_i := big.NewInt(int64(vi))

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
