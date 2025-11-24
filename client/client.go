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
	"os"
	"time"
)

const serverURL = "http://localhost:8080"

// User holds all per-voter cryptographic material and runtime state
type User struct {
	UserID string
	Apk    *big.Int // public key given by authority
	Ask    *big.Int // secret key (decrypted from authority)
	K      []byte   // anamorphic key bytes
	Tmap   map[string]*big.Int
	PP     ElGamal.Params  // ElGamal public parameters
	APP    ElGamal.AParams // anamorphic parameters
	vi     *big.Int        // real vote
	vf     *big.Int        // fake vote
	port   int             // user HTTP listener port
	pkA    *big.Int        // authority public key for encrypted key shipping
	ApkVC  *big.Int        // public key of VC for anamorphic encryption
	dkVC   []byte          // Vote Collector's double key
	conf   [2]*big.Int     // confirmation ciphertext
}

var user *User

func main() {
	userID := os.Args[1] // user ID passed as CLI argument

	// Register user at authority (fetch params, exchange ephemeral keys, receive encrypted secrets)
	if err := RegisterUser(userID); err != nil {
		log.Fatal(err)
	}

	// Start HTTP listener to receive keys, shares, and confirmation from other components
	go startUserListener()

	// Wait until the server signals the start of the voting phase
	for {
		resp, err := http.Get(serverURL + "/status")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		var st map[string]string
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()

		// Stop wainting once phase == voting
		if st["phase"] == "voting" {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Poll until the authority gives successor notification
	var notif map[string]string
	for {
		resp, err := http.Get(fmt.Sprintf("%s/notification?userID=%s", serverURL, user.UserID))
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode == 200 {
			json.NewDecoder(resp.Body).Decode(&notif)
			resp.Body.Close()
			break
		}

		// If still not assigned
		resp.Body.Close()
		time.Sleep(1 * time.Second)
	}

	// Block forever waiting for vote confirmation callback
	select {}
}

func RegisterUser(userID string) error {
	//Fetch public ElGamal parameters from the authority
	url := fmt.Sprintf("%s/fetch?userID=%s", serverURL, userID)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch public parameters: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authority error: %s", body)
	}

	// Authority sends A, P, Q, G (A is authority temporary value)
	var params struct {
		A string `json:"A"`
		P string `json:"P"`
		Q string `json:"Q"`
		G string `json:"G"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&params); err != nil {
		return fmt.Errorf("failed to decode parameters: %v", err)
	}

	// Convert fetched parameters to big.Int
	A := new(big.Int)
	P := new(big.Int)
	Q := new(big.Int)
	G := new(big.Int)
	A.SetString(params.A, 10)
	P.SetString(params.P, 10)
	Q.SetString(params.Q, 10)
	G.SetString(params.G, 10)

	// Initialize User struct
	user = &User{
		UserID: userID,
		Apk:    new(big.Int),
		Ask:    new(big.Int),
		Tmap:   make(map[string]*big.Int),
		pkA:    new(big.Int),
		ApkVC:  new(big.Int),
		dkVC:   nil,
	}

	// Store global ElGamal parameters
	user.PP = ElGamal.Params{P: P, Q: Q, G: G}

	// Compute ephemeral keys for secure key exchange
	pow, _ := rand.Int(rand.Reader, user.PP.Q)       // ephemeral exponent
	sessionK := new(big.Int).Exp(A, pow, user.PP.Q)  // shared DH-like secret
	B := new(big.Int).Exp(user.PP.G, pow, user.PP.Q) // send B = g^pow mod Q to server

	// Register user at authority (send B)
	payload := map[string]string{
		"userID": userID,
		"B":      B.String(),
	}

	buf, _ := json.Marshal(payload)
	resp, err = http.Post(serverURL+"/register", "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authority error: %s", body)
	}

	// Structure for authority registration response
	var data struct {
		Status string            `json:"status"`
		UserID string            `json:"userID"`
		Apk    string            `json:"apk"`
		C0sk   string            `json:"c0sk"`
		C1sk   string            `json:"c1sk"`
		C0dk   string            `json:"c0dk"`
		C1dk   string            `json:"c1dk"`
		Tmap   map[string]string `json:"Tmap"`
		L      int               `json:"L"`
		S      string            `json:"S"`
		T      string            `json:"T"`
		ApkVC  string            `json:"ApkVC"`
		Port   int               `json:"Port"`
		PkA    string            `json:"pkA"`
	}

	// Decode registration response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	user.Apk.SetString(data.Apk, 10)
	user.port = data.Port

	// COnvert Tmap values to big.Int
	for k, v := range data.Tmap {
		bi := new(big.Int)
		bi.SetString(v, 10)
		user.Tmap[k] = bi
	}

	// Convert misc parameters
	S := new(big.Int)
	S.SetString(data.S, 10)
	T := new(big.Int)
	T.SetString(data.T, 10)

	user.pkA.SetString(data.PkA, 10)
	user.ApkVC.SetString(data.ApkVC, 10)

	// Convert encrypted secret keys for decryption
	c0sk := new(big.Int)
	c1sk := new(big.Int)
	c0dk := new(big.Int)
	c1dk := new(big.Int)
	c0sk.SetString(data.C0sk, 10)
	c1sk.SetString(data.C1sk, 10)
	c0dk.SetString(data.C0dk, 10)
	c1dk.SetString(data.C1dk, 10)

	// Decrypt keys using sessionK (authority ecnrypted them with g^(pow*A))
	Ask := ElGamal.Dec(&user.PP, sessionK, c0sk, c1sk)
	KInt := ElGamal.Dec(&user.PP, sessionK, c0dk, c1dk)

	user.K = KInt.Bytes()
	user.Ask = Ask

	// Store anamorphic parameters
	app := ElGamal.AParams{L: data.L, S: S, T: T}
	user.APP = app

	fmt.Printf("[User %s] Registration successful!\n", userID)
	return nil
}

func startUserListener() {
	// Create a new HTTP request multiplexer
	mux := http.NewServeMux()

	// Register HTTP endpoints for callbacks
	mux.HandleFunc("/handle_confirmation", handleConfirmation) // final vote confirmation
	mux.HandleFunc("/confirm", handleFakeVote)                 // push fake vote to malicious PK
	mux.HandleFunc("/handle_key", handleKeyFetch)              // fetch K encrypted to authority
	mux.HandleFunc("/receive", receiveShares)                  // receive shared secrets from other users

	// Listen on the assigned port
	addr := fmt.Sprintf(":%d", user.port)
	log.Printf("[%s] Listening on %s for confirmation\n", user.UserID, addr)

	// Start HTTP server in a gorputine
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("[%s] Listener failed: %v", user.UserID, err)
		}
	}()
}

func handleConfirmation(w http.ResponseWriter, r *http.Request) {
	// Struct to decode incoming JSON vote confirmation
	var req struct {
		UserID string `json:"userID"`
		C0     string `json:"c0"`
		C1     string `json:"c1"`
	}

	// Decode the JSON payload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid vote format", http.StatusBadRequest)
		return
	}

	// Convert string ciphertexts to big.Int
	c0 := new(big.Int)
	c1 := new(big.Int)
	if _, ok := c0.SetString(req.C0, 10); !ok {
		http.Error(w, "invalid c0", http.StatusBadRequest)
		return
	}
	if _, ok := c1.SetString(req.C1, 10); !ok {
		http.Error(w, "invalid c1", http.StatusBadRequest)
		return
	}

	// Save confirmation ciphertext
	user.conf = [2]*big.Int{c0, c1}

	// Decrypt final vote and blind vote for verification
	vf := ElGamal.Dec(&user.PP, user.Ask, c0, c1)
	bi := ElGamal.ADec(user.APP, user.PP, user.K, user.Tmap, c0, c1)

	fmt.Println("Vf:", user.vf, "and conf vf", vf)
	fmt.Println("Vi:", user.vi, "and conf vi", bi)
	if user.vf.Cmp(vf) == 0 && user.vi.Cmp(bi) == 0 {
		log.Println("Vote saved correctly!")
	} else {
		log.Println("Failed confirmation!")
	}

	// Respond OK to authority
	writeJSON(w, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, data any) {
	// Set JSON header and encode response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleKeyFetch(w http.ResponseWriter, r *http.Request) {
	// Convert K []byte → *big.Int
	fmt.Println(user.K)
	bi := new(big.Int).SetBytes(user.K)
	fmt.Println(bi)

	// Encrypt with ElGamal
	c0, c1, _ := ElGamal.Enc(user.PP, user.pkA, bi)

	// Prepare JSON payload
	payload := map[string]any{
		"c0": c0.String(), // big.Int → string
		"c1": c1.String(),
	}

	// Send proper JSON
	writeJSON(w, payload)
}

func receiveShares(w http.ResponseWriter, r *http.Request) {

	// Decode incoming encrypted shares
	var payload struct {
		Ri       string   `json:"ri"` // random value for user
		C0s      []string `json:"c0s"`
		C1s      []string `json:"c1s"`
		NumUsers int      `json:"num_users"` // number of users
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	writeJSON(w, map[string]string{
		"status": "ok",
	})

	// Convert Ri to big.Int
	ri := new(big.Int)
	ri.SetString(payload.Ri, 10)

	// Decrypt all shares and anamoprhic values
	shares := make([]*big.Int, 0)
	kvals := make([]*big.Int, 0)

	for idx := range len(user.K) { // iterate over expected length of K

		c0 := new(big.Int)
		c1 := new(big.Int)

		c0.SetString(payload.C0s[idx], 10)
		c1.SetString(payload.C1s[idx], 10)

		// Decrypt share (si) and anamorphic value (ki)
		si := ElGamal.Dec(&user.PP, user.Ask, c0, c1)
		ki := ElGamal.ADec(user.APP, user.PP, user.K, user.Tmap, c0, c1)
		fmt.Println(ki)

		shares = append(shares, si)
		kvals = append(kvals, ki)
	}

	// Remove zer-padded shares (keep only real values)
	cleanShares := make([]*big.Int, 0)
	for _, s := range shares {
		if s.Sign() != 0 { // ignore padded zeros
			cleanShares = append(cleanShares, s)
		}
	}

	// Convert recovered K-values to bytes for VC
	kBytes := make([]byte, 0)
	for _, kv := range kvals {
		kBytes = append(kBytes, byte(kv.Int64()))
	}
	user.dkVC = kBytes

	//---------------------------------------------------------
	// Continue the voting protocol
	//---------------------------------------------------------

	// Generate real and fake votes
	candidateRand, _ := rand.Int(rand.Reader, big.NewInt(15))   // 0..14
	candidate := new(big.Int).Add(candidateRand, big.NewInt(1)) // 1..15
	fakeRand, _ := rand.Int(rand.Reader, big.NewInt(5))         // 0..4
	vf := new(big.Int).Add(fakeRand, big.NewInt(16))            // 16..20

	user.vf = vf
	user.vi = candidate

	fmt.Println("Fake vote: ", vf, "and real one", candidate)

	// Compute blind vote using the decrypted shares
	bi := ElGamal.ComputeBlindVotes(int(candidate.Int64()), ri, cleanShares, user.PP, user.APP)

	// Encrypt vote for VC
	c0, c1, _ := ElGamal.AEnc(user.APP, user.PP, user.dkVC, user.ApkVC, vf, bi)
	req := map[string]string{
		"userID": user.UserID,
		"c0":     c0.String(),
		"c1":     c1.String(),
	}
	buf, _ := json.Marshal(req)
	vcURL := "http://localhost:8090/store_vote" // VC address (change if different)
	resp, err := http.Post(vcURL, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		log.Printf("[User] Failed to push vote to VC: %v", err)
		return
	}
	resp.Body.Close()

	writeJSON(w, map[string]any{"status": "ok", "pushed": true})
}

func handleFakeVote(w http.ResponseWriter, r *http.Request) {
	// Decode malicious PK from JSON
	var body struct {
		PkEvil string `json:"pk_evil"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Encrypt Ask under malicious PK
	pkString := body.PkEvil
	pkE := new(big.Int)
	pkE.SetString(pkString, 10)
	c0k, c1k, _ := ElGamal.Enc(user.PP, pkE, user.Ask)

	// Include confirmation ciphertexts
	payload := map[string]string{
		"c0k":    c0k.String(),
		"c1k":    c1k.String(),
		"c0conf": user.conf[0].String(),
		"c1conf": user.conf[1].String(),
	}

	// Respond as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
	}
}
