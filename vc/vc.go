package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"bytes"
	"crypto/rand"
	"encoding/hex"
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

var vc = &VoteCollector{Votes: make([]*big.Int, 0)}

type VoteCollector struct {
	AskVC   *big.Int
	ApkVC   *big.Int
	K       []byte
	Tmap    map[string]*big.Int
	PP      ElGamal.Params
	APP     ElGamal.AParams
	randoms map[string]*big.Int
	shares  map[string][]*big.Int
	Votes   []*big.Int
	users   map[string]*User
	pkA     *big.Int
}

type User struct {
	userID string
	ApkU   *big.Int
	dkU    []byte
	port   int
}

func main() {
	fmt.Println("[VC] Registering with authority...")

	// Register VC with authority
	resp, err := http.Get(serverURL + "/register_vc")
	if err != nil {
		log.Fatalf("Failed to register VC: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Authority error: %s", body)
	}

	// Parse authority response
	var data struct {
		Status string            `json:"status"`
		Sk     string            `json:"sk"`
		Pk     string            `json:"pk"`
		K      string            `json:"K"`
		Tmap   map[string]string `json:"Tmap"`
		P      string            `json:"P"`
		Q      string            `json:"Q"`
		G      string            `json:"G"`
		L      int               `json:"L"`
		S      string            `json:"S"`
		T      string            `json:"T"`
		PkA    string            `json:"pkA"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatalf("Invalid response: %v", err)
	}

	// Decode VC's K
	KBytes, err := hex.DecodeString(data.K)
	if err != nil {
		log.Fatalf("Failed to decode K: %v", err)
	}

	// Initialize VC structure
	vc = &VoteCollector{
		AskVC:   new(big.Int),
		ApkVC:   new(big.Int),
		K:       KBytes,
		Tmap:    make(map[string]*big.Int),
		PP:      ElGamal.Params{},
		APP:     ElGamal.AParams{},
		pkA:     new(big.Int),
		users:   make(map[string]*User),
		randoms: make(map[string]*big.Int),
		shares:  make(map[string][]*big.Int),
	}

	// Set VC keys
	if _, ok := vc.AskVC.SetString(data.Sk, 10); !ok {
		log.Fatal("Invalid Sk from authority")
	}
	if _, ok := vc.ApkVC.SetString(data.Pk, 10); !ok {
		log.Fatal("Invalid Pk from authority")
	}

	// Convert Tmap values
	for k, v := range data.Tmap {
		bi := new(big.Int)
		if _, ok := bi.SetString(v, 10); !ok {
			log.Fatalf("Invalid Tmap value for key %s: %s", k, v)
		}
		vc.Tmap[k] = bi
	}

	// Set ElGamal parameters
	vc.PP.P = new(big.Int)
	vc.PP.Q = new(big.Int)
	vc.PP.G = new(big.Int)
	vc.PP.P.SetString(data.P, 10)
	vc.PP.Q.SetString(data.Q, 10)
	vc.PP.G.SetString(data.G, 10)

	vc.APP.L = data.L
	vc.APP.S = new(big.Int)
	vc.APP.T = new(big.Int)
	vc.APP.S.SetString(data.S, 10)
	vc.APP.T.SetString(data.T, 10)

	if _, ok := vc.pkA.SetString(data.PkA, 10); !ok {
		log.Fatal("Invalid pkA from authority")
	}

	fmt.Println("[VC] Registration successful.")

	// Start VC listener
	go startVCListener()

	// Wait until authority signals ready_for_group
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

	// Extract user IDs from vc.users
	userIDs := make([]string, 0, len(vc.users))
	for id := range vc.users {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs) // deterministic ring

	// Build successor ring
	successors := make(map[string]string)
	for i := 0; i < len(userIDs); i++ {
		successors[userIDs[i]] = userIDs[(i+1)%len(userIDs)]
	}

	// Generate random ri and split into shares
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

	for i, receiverID := range userIDs {
		sharesForUser := make([]*big.Int, 0, len(userIDs))
		for _, ownerID := range userIDs {
			sharesForUser = append(sharesForUser, distribute[ownerID][i])
		}
		vc.shares[receiverID] = sharesForUser
	}

	vc.randoms = randoms
	fmt.Println(randoms)
	fmt.Println(distribute)

	// Send shares to each user
	for _, ownerID := range userIDs {
		receiver := vc.users[ownerID]
		c0sStr := make([]string, 0)
		c1sStr := make([]string, 0)
		shares := vc.shares[ownerID] // share owner->receiver
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
			fmt.Println(sVal)
			fmt.Println(kVal)

			Kparam := vc.users[ownerID].dkU
			c0, c1, _ := ElGamal.AEnc(vc.APP, vc.PP, Kparam, receiver.ApkU, sVal, kVal)

			c0sStr = append(c0sStr, c0.String())
			c1sStr = append(c1sStr, c1.String())
		}
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

	select {} // Keep VC running
}

func startVCListener() {
	http.HandleFunc("/store_vote", handleStoreVote)
	http.HandleFunc("/handle_key", handleKeyFetch)
	http.HandleFunc("/send_user", handleSendUser)
	fmt.Println("[VC] listening on :8090 for pushed votes")
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func handleStoreVote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userID"`
		C0     string `json:"c0"`
		C1     string `json:"c1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	c0 := new(big.Int)
	c0.SetString(req.C0, 10)
	c1 := new(big.Int)
	c1.SetString(req.C1, 10)

	fmt.Println(vc.K)

	vfi := ElGamal.Dec(&vc.PP, vc.AskVC, c0, c1)
	bi := ElGamal.ADec(vc.APP, vc.PP, vc.K, vc.Tmap, c0, c1)

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

	sumShares := big.NewInt(0)
	for _, s := range vc.shares[req.UserID] {
		sumShares.Add(sumShares, s)
	}

	total = total.Sub(total, vc.randoms[req.UserID])
	vote := total.Add(total, sumShares)
	vc.Votes = append(vc.Votes, vote)
	fmt.Println("Vote for user", req.UserID, "was", vote)

	pk := vc.users[req.UserID].ApkU
	K := vc.users[req.UserID].dkU
	// Re-encrypt vfi and bi
	c0, c1, _ = ElGamal.AEnc(vc.APP, vc.PP, K, pk, vfi, vote)

	// send verification to the server first, they forward it to user
	payload := map[string]any{
		"userID": vc.users[req.UserID].userID,
		"c0":     c0.String(),
		"c1":     c1.String(),
	}

	byt, _ := json.Marshal(payload)
	log.Printf("[VC] Received re-encrypted vote for user %s", req.UserID)
	w.WriteHeader(http.StatusOK)
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
	if len(vc.Votes) == len(vc.users) {

		// --- 1. Fetch candidates ---
		resp, err := http.Get(serverURL + "/candidates")
		if err != nil {
			fmt.Println("Failed to fetch candidates:", err)
			return
		}
		var candidates []string
		json.NewDecoder(resp.Body).Decode(&candidates)
		resp.Body.Close()

		// --- 2. Vote counters ---
		voteCounts := make([]int, len(candidates))

		// --- 3. Count *big.Int* votes ---
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

		// --- 4. Print results ---
		for i, candidate := range candidates {
			fmt.Printf("Candidate %s got %d votes\n", candidate, voteCounts[i])
		}
	}

}

func handleKeyFetch(w http.ResponseWriter, r *http.Request) {
	bi := new(big.Int).SetBytes(vc.K)

	c0, c1, _ := ElGamal.Enc(vc.PP, vc.pkA, bi)

	payload := map[string]any{
		"c0": c0.String(),
		"c1": c1.String(),
	}

	// Send proper JSOn
	writeJSON(w, payload)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleSendUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// JSON structure sent by the authority/user
	var payload struct {
		ID   string   `json:"id"`
		Port int      `json:"port"`
		PkU  string   `json:"pkU"`
		C0s  []string `json:"c0s"`
		C1s  []string `json:"c1s"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Convert PK string to *big.Int
	pk := new(big.Int)
	if _, ok := pk.SetString(payload.PkU, 10); !ok {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	// Convert C0s/C1s from strings to *big.Int
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
