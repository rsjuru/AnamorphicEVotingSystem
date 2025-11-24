package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"sort"
	"time"
)

const serverURL = "http://localhost:8080"

// Global VC instance
var vc = &VoteCollector{Votes: make([]*big.Int, 0)}

// Represents the vote collector with keys, shares, users, votes and parameters
type VoteCollector struct {
	AskVC   *big.Int // VC secret key
	ApkVC   *big.Int // VC public key
	K       []byte   // VC double key
	Tmap    map[string]*big.Int
	PP      ElGamal.Params        // ElGamal public parameters
	APP     ElGamal.AParams       // Anamorphic parameters
	randoms map[string]*big.Int   // Random values ri for users
	shares  map[string][]*big.Int // Secret shares distributed among users
	Votes   []*big.Int            // Collected votes
	users   map[string]*User      // Registered users
	pkA     *big.Int              // Authority public key
}

// User struct
type User struct {
	userID string   // User ID
	ApkU   *big.Int // User public key
	dkU    []byte   // User double key
	port   int      // Port for user communication
}

func main() {
	// VC registers with authority to obtain keys
	if err := RegisterVC(); err != nil {
		log.Fatal(err)
	}

	// Start VC listener in background to receive messages from users
	go startVCListener()

	// Wait for authority signal to set up voting group and shares
	if err := SetupVotingGroup(); err != nil {
		log.Fatal(err)
	}

	select {} // Keep VC running
}

// -----------------------
// Registration Phase
// -----------------------
// VC fetches public parameters from authority and establishes keys
func RegisterVC() error {
	fmt.Println("[VC] Registering with authority...")

	// Fetch authority parameters
	url := fmt.Sprintf("%s/fetch?userID=%s", serverURL, "VC")
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch public parameters: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authority error: %s", body)
	}

	// Decode authority parameters: A, P, Q, G
	var params struct {
		A string `json:"A"`
		P string `json:"P"`
		Q string `json:"Q"`
		G string `json:"G"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&params); err != nil {
		return fmt.Errorf("failed to decode parameters: %v", err)
	}

	// Convert parameters to big.Int
	A := new(big.Int)
	P := new(big.Int)
	Q := new(big.Int)
	G := new(big.Int)
	A.SetString(params.A, 10)
	P.SetString(params.P, 10)
	Q.SetString(params.Q, 10)
	G.SetString(params.G, 10)

	// Initialize VC struct
	vc = &VoteCollector{
		AskVC:   new(big.Int),
		ApkVC:   new(big.Int),
		Tmap:    make(map[string]*big.Int),
		PP:      ElGamal.Params{},
		APP:     ElGamal.AParams{},
		pkA:     new(big.Int),
		users:   make(map[string]*User),
		randoms: make(map[string]*big.Int),
		shares:  make(map[string][]*big.Int),
	}
	vc.PP = ElGamal.Params{P: P, Q: Q, G: G}

	// Generate ephemeral session key
	pow, _ := rand.Int(rand.Reader, vc.PP.Q)
	sessionK := new(big.Int).Exp(A, pow, vc.PP.Q)
	B := new(big.Int).Exp(vc.PP.G, pow, vc.PP.Q)

	// Send registration payload to authority
	payload := map[string]string{"B": B.String()}
	buf, _ := json.Marshal(payload)
	resp, err = http.Post(serverURL+"/register_vc", "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authority error: %s", body)
	}

	// Decode authority response
	var data struct {
		Status string            `json:"status"`
		Pk     string            `json:"pk"`
		C0sk   string            `json:"c0sk"`
		C1sk   string            `json:"c1sk"`
		C0dk   string            `json:"c0dk"`
		C1dk   string            `json:"c1dk"`
		Tmap   map[string]string `json:"Tmap"`
		L      int               `json:"L"`
		S      string            `json:"S"`
		T      string            `json:"T"`
		PkA    string            `json:"pkA"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("invalid response: %v", err)
	}

	// Set VC public key
	if _, ok := vc.ApkVC.SetString(data.Pk, 10); !ok {
		return fmt.Errorf("invalid Pk from authority")
	}

	// Populate Tmap
	for k, v := range data.Tmap {
		bi := new(big.Int)
		if _, ok := bi.SetString(v, 10); !ok {
			return fmt.Errorf("invalid Tmap value for key %s: %s", k, v)
		}
		vc.Tmap[k] = bi
	}

	// Set anamorphic parameters
	vc.APP.L = data.L
	vc.APP.S = new(big.Int)
	vc.APP.T = new(big.Int)
	vc.APP.S.SetString(data.S, 10)
	vc.APP.T.SetString(data.T, 10)

	// Decrypt VC secret keys using session key
	c0sk := new(big.Int)
	c1sk := new(big.Int)
	c0dk := new(big.Int)
	c1dk := new(big.Int)
	c0sk.SetString(data.C0sk, 10)
	c1sk.SetString(data.C1sk, 10)
	c0dk.SetString(data.C0dk, 10)
	c1dk.SetString(data.C1dk, 10)

	Ask := ElGamal.Dec(&vc.PP, sessionK, c0sk, c1sk)
	KInt := ElGamal.Dec(&vc.PP, sessionK, c0dk, c1dk)
	vc.K = KInt.Bytes()
	vc.AskVC = Ask

	if _, ok := vc.pkA.SetString(data.PkA, 10); !ok {
		return fmt.Errorf("invalid pkA from authority")
	}

	fmt.Println("[VC] Registration successful.")
	return nil
}

// -----------------------
// Voting Group Setup & Shares
// -----------------------
// Waits for authority signal, generates random ri for each user,
// splits ri into shares, and sends encrypted shares to users
func SetupVotingGroup() error {
	fmt.Println("[VC] Waiting for authority to signal ready_for_group...")

	// --- Wait for ready signal ---
	for {
		resp, err := http.Get(serverURL + "/status")
		if err != nil {
			log.Println("[VC] status request failed:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		var st map[string]string
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if st["phase"] == "ready_for_group" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Extract user IDs and sort
	userIDs := make([]string, 0, len(vc.users))
	for id := range vc.users {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs)

	// Build successor ring for distributed computations
	successors := make(map[string]string)
	for i := 0; i < len(userIDs); i++ {
		successors[userIDs[i]] = userIDs[(i+1)%len(userIDs)]
	}

	// Generate random ri for each user and split into shares
	low := big.NewInt(50)
	high := big.NewInt(100)
	rangeVal := new(big.Int).Sub(high, low)

	randoms := make(map[string]*big.Int)
	distribute := make(map[string][]*big.Int)

	for _, user := range userIDs {
		r_i, _ := rand.Int(rand.Reader, rangeVal)
		r_i.Add(r_i, low) // ensure r_i in [50, 100)
		randoms[user] = r_i
		splits := ElGamal.SplitSecret(r_i, len(userIDs))
		distribute[user] = append(distribute[user], splits...)
	}

	// Assing shares to each user
	for i, receiverID := range userIDs {
		sharesForUser := make([]*big.Int, 0, len(userIDs))
		for _, ownerID := range userIDs {
			sharesForUser = append(sharesForUser, distribute[ownerID][i])
		}
		vc.shares[receiverID] = sharesForUser
	}
	vc.randoms = randoms

	fmt.Println("[VC] Randoms:", randoms)
	fmt.Println("[VC] Distribute shares:", distribute)

	// Send shares to users via HTTP POST
	for _, ownerID := range userIDs {
		receiver := vc.users[ownerID]
		c0sStr := make([]string, 0)
		c1sStr := make([]string, 0)
		shares := vc.shares[ownerID] // shares for receiver
		kBytes := vc.K
		Klen := len(kBytes)
		N := 1
		if Klen > N {
			N = Klen
		}

		// Encrypt share using anamorphic encryption
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

			Kparam := vc.users[ownerID].dkU
			c0, c1, _ := ElGamal.AEnc(vc.APP, vc.PP, Kparam, receiver.ApkU, sVal, kVal)

			c0sStr = append(c0sStr, c0.String())
			c1sStr = append(c1sStr, c1.String())
		}

		// Prepare payload to send to user
		payload := map[string]interface{}{
			"ri":        vc.randoms[ownerID].String(),
			"c0s":       c0sStr,
			"c1s":       c1sStr,
			"num_users": len(userIDs),
		}

		body, _ := json.Marshal(payload)
		url := fmt.Sprintf("http://localhost:%d/receive", receiver.port)
		if _, err := http.Post(url, "application/json", bytes.NewReader(body)); err != nil {
			fmt.Println("Failed to send to", ownerID, ":", err)
		}
	}

	return nil
}

// -----------------------
// Listener & Handlers
// -----------------------

// Sets up HTTP endpoints to handle incoming requests
// from users and authority.
func startVCListener() {
	http.HandleFunc("/store_vote", handleStoreVote) // Endpoint for receiving votes from users
	http.HandleFunc("/handle_key", handleKeyFetch)  // Endpoint for key requests
	http.HandleFunc("/send_user", handleSendUser)   // Endpoint for receiving user info
	fmt.Println("[VC] listening on :8090 for pushed votes")
	log.Fatal(http.ListenAndServe(":8090", nil)) // Start HTTP server
}

// Receives an encrypted vote from a user, decrypts, re-encrypts,
// updates internal vote tally, and optionally prints final results.
func handleStoreVote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userID"` // User ID sending the vote
		C0     string `json:"c0"`     // Encrypted vote part 0
		C1     string `json:"c1"`     // Encrypted vote part 1
	}
	// Decode JSON request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Convert string ciphertext to big.Int
	c0 := new(big.Int)
	c0.SetString(req.C0, 10)
	c1 := new(big.Int)
	c1.SetString(req.C1, 10)

	fmt.Println(vc.K)

	// Decrypt using VC's secret key to obtaing the fake vote
	vfi := ElGamal.Dec(&vc.PP, vc.AskVC, c0, c1)

	// Decrypt using anamorphic scheme to get the real vote
	bi := ElGamal.ADec(vc.APP, vc.PP, vc.K, vc.Tmap, c0, c1)

	// Handle signed votes
	total := big.NewInt(0)
	S := big.NewInt(int64(vc.APP.L))
	half := new(big.Int).Div(S, big.NewInt(2))

	b := new(big.Int).Set(bi)
	// convert to signed representation in range [-L/2, L/2)
	if b.Cmp(half) > 0 {
		b.Sub(b, S)
	}
	// accumulate total
	total.Add(total, b)

	// Sum secret shares for this user
	sumShares := big.NewInt(0)
	for _, s := range vc.shares[req.UserID] {
		sumShares.Add(sumShares, s)
	}

	// Compute final vote: total = bi + sum(shares) - r_i
	total = total.Sub(total, vc.randoms[req.UserID])
	vote := total.Add(total, sumShares)

	// Append vote to VC's internal votes list
	vc.Votes = append(vc.Votes, vote)
	fmt.Println("Vote for user", req.UserID, "was", vote)

	// Re-encrypt votes for verification by user
	pk := vc.users[req.UserID].ApkU
	K := vc.users[req.UserID].dkU
	c0, c1, _ = ElGamal.AEnc(vc.APP, vc.PP, K, pk, vfi, vote)

	// Send verification to user
	payload := map[string]any{
		"userID": vc.users[req.UserID].userID,
		"c0":     c0.String(),
		"c1":     c1.String(),
	}
	byt, _ := json.Marshal(payload)
	log.Printf("[VC] Received re-encrypted vote for user %s", req.UserID)
	w.WriteHeader(http.StatusOK)

	// Send confirmation to user's endpoint
	callbackURL := fmt.Sprintf("http://localhost:%d/handle_confirmation", vc.users[req.UserID].port)
	go func() {
		resp, err := http.Post(callbackURL, "application/json", bytes.NewBuffer(byt))
		if err != nil {
			log.Printf("[VC] Failed to send confirmation: %v", err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Count votes if all users have voted
	if len(vc.Votes) == len(vc.users) {

		// Fetch list of candidates
		resp, err := http.Get(serverURL + "/candidates")
		if err != nil {
			fmt.Println("Failed to fetch candidates:", err)
			return
		}
		var candidates []string
		json.NewDecoder(resp.Body).Decode(&candidates)
		resp.Body.Close()

		// Initialize vote counters
		voteCounts := make([]int, len(candidates))

		// Count votes
		for _, v := range vc.Votes {
			if v == nil {
				continue
			}

			// Convert *big.Int → int
			voteInt := int(v.Int64())

			// Votes start from 1 → convert to 0-based index
			index := voteInt - 1

			if index >= 0 && index < len(candidates) {
				voteCounts[index]++
			} else {
				fmt.Println("Invalid vote value:", v.String())
			}
		}

		// Print final vote tally
		for i, candidate := range candidates {
			fmt.Printf("Candidate %s got %d votes\n", candidate, voteCounts[i])
		}
	}

}

// Handles requests from authority to fetch the VC's double key
func handleKeyFetch(w http.ResponseWriter, r *http.Request) {
	bi := new(big.Int).SetBytes(vc.K)

	// Encrypt K using authority's public key
	c0, c1, _ := ElGamal.Enc(vc.PP, vc.pkA, bi)

	payload := map[string]any{
		"c0": c0.String(),
		"c1": c1.String(),
	}

	// Respond with JSON
	writeJSON(w, payload)
}

// Receives user info (ID, port, public key, and encrypted double key)
// from authority and stores it in VC's users map
func handleSendUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// JSON structure sent by the authority/user
	var payload struct {
		ID   string   `json:"id"`   // User ID
		Port int      `json:"port"` // User port
		PkU  string   `json:"pkU"`  // User public key
		C0s  []string `json:"c0s"`  // Encrypted dk part 0
		C1s  []string `json:"c1s"`  // Encrypted dk part 1
	}

	// Decode JSON payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Convert public key string to big.Int
	pk := new(big.Int)
	if _, ok := pk.SetString(payload.PkU, 10); !ok {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	// Convert encrypted key strings to big.Int
	c0s := make([]*big.Int, len(payload.C0s))
	for i, s := range payload.C0s {
		bi := new(big.Int)
		if _, ok := bi.SetString(s, 10); !ok {
			http.Error(w, fmt.Sprintf("invalid C0s[%d]", i), http.StatusBadRequest)
			return
		}
		c0s[i] = bi
	}

	c1s := make([]*big.Int, len(payload.C1s))
	for i, s := range payload.C1s {
		bi := new(big.Int)
		if _, ok := bi.SetString(s, 10); !ok {
			http.Error(w, fmt.Sprintf("invalid C1s[%d]", i), http.StatusBadRequest)
			return
		}
		c1s[i] = bi
	}

	// Decrypt double key using VC key K
	dkU := make([]byte, 0)
	for i := range len(c0s) {
		b := ElGamal.ADec(vc.APP, vc.PP, vc.K, vc.Tmap, c0s[i], c1s[i])
		dkU = append(dkU, byte(b.Int64()))
	}

	// Save user info in VC's map
	vcUser := User{
		userID: payload.ID,
		port:   payload.Port,
		ApkU:   pk,
		dkU:    dkU,
	}

	if vc.users == nil {
		vc.users = make(map[string]*User)
	}

	vc.users[vcUser.userID] = &vcUser

	// Respond OK
	writeJSON(w, map[string]string{
		"status": "ok",
	})

	log.Printf("[VC] Received user info: %s", vcUser.userID)
}

// Helper function: write JSON response
func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
