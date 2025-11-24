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
	"sync"
)

// ----------------------
// Structs for Authority
// ----------------------

// Represents a registered voter
type User struct {
	UserID    string
	Apk       *big.Int // user's public key
	Tmap      map[string]*big.Int
	HasVoted  bool
	Successor string
	Port      int
}

// VoteCollector stores VC info
type VoteCollector struct {
	ApkVC *big.Int
	Tmap  map[string]*big.Int
}

// Represents the election authority
type Authority struct {
	PP         ElGamal.Params      // ElGamal public params
	APP        ElGamal.AParams     // Anamorphic params
	PkA        *big.Int            // authority public key
	skA        *big.Int            // authority secret key
	Candidates []string            // list of candidates
	VC         *VoteCollector      // registered vote collector
	Users      map[string]*User    // registeres users
	mu         sync.Mutex          // mutex for concurrent access
	sessionAs  map[string]*big.Int // emphemeral session keys for users
}

var (
	auth      *Authority
	users     = make(map[string]*User)
	sessionAs = make(map[string]*big.Int)

	phase    = "waiting" // current system phase
	maxUsers = 10        // max users to wait for before group setup
)

func main() {
	setUpAuthority() // initialize authority keys, params, candidates

	// HTTP endpoints
	http.HandleFunc("/register_vc", handleVCRegistration)
	http.HandleFunc("/register", handleUserRegistration)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/candidates", handleCandidates)
	http.HandleFunc("/register_evil", handleEvilRegistration)
	http.HandleFunc("/fetch", handleFetchParameters)

	fmt.Println("=== Authority setup complete ===")
	fmt.Println("Listening on http://localhost:8080 ...")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Helper: write JSON response
func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// -------- Handlers --------

// Registers the vote collector
func handleVCRegistration(w http.ResponseWriter, r *http.Request) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	// reject if VC already exists
	if auth.VC != nil {
		http.Error(w, "VC already registered", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse B sent by VC for session key agreement
	var req struct {
		B string `json:"B"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	B := new(big.Int)
	B.SetString(req.B, 10)

	// Compute session key
	sessionK := new(big.Int).Exp(B, auth.sessionAs["VC"], auth.PP.Q)
	sessionpK := new(big.Int).Exp(auth.PP.G, sessionK, auth.PP.P)

	// ElGamal keygen for VC
	skVC, pkVC, _ := ElGamal.KGen(&auth.PP)
	c0sk, c1sk, _ := ElGamal.Enc(auth.PP, sessionpK, skVC)

	// Anamorphic keygen for VC
	K, Tmap, _ := ElGamal.AGen(auth.APP.L, auth.PP, pkVC)
	KInt := new(big.Int).SetBytes(K)
	c0dk, c1dk, _ := ElGamal.Enc(auth.PP, sessionpK, KInt)

	// Save VC info
	vc := &VoteCollector{
		ApkVC: pkVC,
		Tmap:  Tmap,
	}

	auth.VC = vc

	// Respond with VC keys and shares
	resp := map[string]interface{}{
		"status": "ok",
		"pk":     pkVC.String(),
		"c0sk":   c0sk.String(),
		"c1sk":   c1sk.String(),
		"c0dk":   c0dk.String(),
		"c1dk":   c1dk.String(),
		"Tmap":   bigMapToStringMap(Tmap),
		"L":      auth.APP.L,
		"S":      auth.APP.S.String(),
		"T":      auth.APP.T.String(),
		"pkA":    auth.PkA.String(),
	}

	json.NewEncoder(w).Encode(resp)
	fmt.Println("[Authority] VC registered successfully.")
}

// ---------------------- Authority Setup ----------------------
func setUpAuthority() {
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

	// Generate authority keypair
	skA, pkA, err := ElGamal.KGen(&pp)
	if err != nil {
		log.Fatalf("KGen (Authority) failed: %v", err)
	}
	log.Println("Authority keypair generated.")

	// Anamorphic parameters
	L := 5000
	S := big.NewInt(int64(L))
	T := big.NewInt(int64(L))
	ap := ElGamal.AParams{L: L, S: S, T: T}

	// Candidates: 15 good + 5 evil
	candidates := make([]string, 0, 20)
	for i := 1; i <= 15; i++ {
		candidates = append(candidates, fmt.Sprintf("GoodCandidate%02d", i))
	}
	for i := 1; i <= 5; i++ {
		candidates = append(candidates, fmt.Sprintf("EvilCandidate%02d", i))
	}

	// Initialize authority struct
	auth = &Authority{
		PP:         pp,
		APP:        ap,
		PkA:        pkA,
		skA:        skA,
		Candidates: candidates,
		Users:      users,
		sessionAs:  sessionAs,
		VC:         nil,
	}
}

// ---------------------- Fetch Parameters ----------------------
func handleFetchParameters(w http.ResponseWriter, r *http.Request) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	// Get userID from query
	userID := r.URL.Query().Get("userID")
	if userID == "" {
		http.Error(w, "missing userID", http.StatusBadRequest)
		return
	}

	if _, exists := auth.Users[userID]; exists {
		http.Error(w, "user already registered", http.StatusBadRequest)
		return
	}

	// Optionally: log or use userID for something
	fmt.Printf("[Authority] %s requested public parameters\n", userID)

	// Generate ephemeral A for this user
	pow, _ := rand.Int(rand.Reader, auth.PP.Q)
	A := new(big.Int).Exp(auth.PP.G, pow, auth.PP.Q)
	auth.sessionAs[userID] = pow

	// Respond with public parameters
	resp := map[string]string{
		"A": A.String(),
		"P": auth.PP.P.String(),
		"Q": auth.PP.Q.String(),
		"G": auth.PP.G.String(),
	}

	writeJSON(w, resp)
}

// ---------------- User Registration ----------------
func handleUserRegistration(w http.ResponseWriter, r *http.Request) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	// Only POST allowed
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if auth.VC == nil {
		http.Error(w, "cannot register, VC does not exist.", http.StatusBadRequest)
		return
	}

	// Decode JSON payload from client
	var req struct {
		UserID string `json:"userID"`
		B      string `json:"B"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	userID := req.UserID
	if userID == "" {
		http.Error(w, "missing userID", http.StatusBadRequest)
		return
	}

	if _, exists := auth.Users[userID]; exists {
		http.Error(w, "user already registered", http.StatusBadRequest)
		return
	}

	// Parse B sent by client
	B := new(big.Int)
	B.SetString(req.B, 10)

	sessionK := new(big.Int).Exp(B, auth.sessionAs[userID], auth.PP.Q)
	sessionpK := new(big.Int).Exp(auth.PP.G, sessionK, auth.PP.P)

	// Generate ElGamal-like keypair for user
	skU, pkU, _ := ElGamal.KGen(&auth.PP)
	c0sk, c1sk, _ := ElGamal.Enc(auth.PP, sessionpK, skU)

	// Generate anamorphic keys for user
	K, Tmap, _ := ElGamal.AGen(auth.APP.L, auth.PP, pkU)
	KInt := new(big.Int).SetBytes(K)
	c0dk, c1dk, _ := ElGamal.Enc(auth.PP, sessionpK, KInt)

	// Create and save user entry
	user := &User{
		UserID: userID,
		Apk:    pkU,
		Tmap:   Tmap,
	}
	auth.Users[userID] = user
	port := 8100 + len(auth.Users)
	auth.Users[userID].Port = port

	url := "http://localhost:8090/handle_key"
	resp, _ := http.Get(url)

	var payload struct {
		C0 string `json:"c0"`
		C1 string `json:"c1"`
	}

	c0 := new(big.Int)
	c1 := new(big.Int)
	if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil {
		c0.SetString(payload.C0, 10)
		c1.SetString(payload.C1, 10)
	}

	Kint := ElGamal.Dec(&auth.PP, auth.skA, c0, c1)
	VCbytes := Kint.Bytes()

	c0s := make([]*big.Int, len(K))
	c1s := make([]*big.Int, len(K))
	for i, b := range K {
		bi := big.NewInt(int64(b))
		iBig := big.NewInt(int64(i))
		c0New, c1New, _ := ElGamal.AEnc(auth.APP, auth.PP, VCbytes, auth.VC.ApkVC, iBig, bi)
		c0s[i] = c0New
		c1s[i] = c1New
	}

	// --- Prepare user info for VC ---
	type UserInfo struct {
		ID   string   `json:"id"`
		Port int      `json:"port"`
		PkU  string   `json:"pkU"` // public key as string
		C0s  []string `json:"c0s"` // anamorphic shares
		C1s  []string `json:"c1s"` // anamorphic shares
	}

	c0Strs := make([]string, len(c0s))
	c1Strs := make([]string, len(c1s))
	for i := range c0s {
		c0Strs[i] = c0s[i].String()
		c1Strs[i] = c1s[i].String()
	}

	userInfo := UserInfo{
		ID:   userID,
		Port: port,
		PkU:  pkU.String(),
		C0s:  c0Strs,
		C1s:  c1Strs,
	}

	// --- Send user info to VC ---
	vcURL := "http://localhost:8090/send_user"
	body, _ := json.Marshal(userInfo)
	respVC, err := http.Post(vcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[Authority] Failed to send user info to VC: %v", err)
	} else {
		io.Copy(io.Discard, respVC.Body) // read and discard
		respVC.Body.Close()
		log.Printf("[Authority] Sent user %s info to VC", userID)
	}

	// Prepare JSON response
	respp := map[string]interface{}{
		"status": "ok",
		"userID": userID,
		"apk":    pkU.String(),
		"c0sk":   c0sk.String(),
		"c1sk":   c1sk.String(),
		"c0dk":   c0dk.String(),
		"c1dk":   c1dk.String(),
		"Tmap":   bigMapToStringMap(Tmap),
		"L":      auth.APP.L,
		"S":      auth.APP.S.String(),
		"T":      auth.APP.T.String(),
		"ApkVC":  auth.VC.ApkVC.String(),
		"pkA":    auth.PkA.String(),
		"Port":   port,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respp)

	fmt.Printf("[Authority] User %s registered.\n", userID)

	// --- check if enough users have registered ---
	// --- check if enough users have registered ---
	if len(auth.Users) == maxUsers {
		log.Printf("[Authority] %d users registered. System ready for group setup.", maxUsers)

		// Move to next phase so VC can detect it
		phase = "ready_for_group"

		// Optional: notify VC immediately (if you want proactive push instead of polling)
		vcReadyURL := "http://localhost:8090/notify_ready"
		payload := map[string]string{"status": "ready_for_group"}
		buf, _ := json.Marshal(payload)
		http.Post(vcReadyURL, "application/json", bytes.NewBuffer(buf))
	}

}

// ---------------- HELPERS ----------------

// Convert map[string]*big.Int -> map[string]string for JSON
func bigMapToStringMap(m map[string]*big.Int) map[string]string {
	smap := make(map[string]string)
	for k, v := range m {
		smap[k] = v.String()
	}
	return smap
}

// Status endpoint
func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"phase": phase})
}

// Return candidate list
func handleCandidates(w http.ResponseWriter, r *http.Request) {
	// Only allow GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth.mu.Lock()
	candidates := make([]string, len(auth.Candidates))
	copy(candidates, auth.Candidates)
	auth.mu.Unlock()

	writeJSON(w, candidates)
}

// Register the "evil" actor (attacker) and return keys + user info
func handleEvilRegistration(w http.ResponseWriter, r *http.Request) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	// Generate ElGamal keypair for evil entity
	sk, pk, _ := ElGamal.KGen(&auth.PP)

	type UserInfo struct {
		UserID string
		Port   int
	}

	// Form vector for userIDs and correspondig ports
	vec := make([]UserInfo, 0)
	for _, user := range auth.Users {
		vec = append(vec, UserInfo{
			UserID: user.UserID,
			Port:   user.Port,
		})
	}

	// Prepare JSON response
	type Response struct {
		Status string     `json:"status"`
		Sk     string     `json:"sk"`
		Pk     string     `json:"pk"`
		P      string     `json:"P"`
		Q      string     `json:"Q"`
		G      string     `json:"G"`
		Vec    []UserInfo `json:"users"`
	}

	resp := Response{
		Status: "ok",
		Sk:     sk.String(),
		Pk:     pk.String(),
		P:      auth.PP.P.String(),
		Q:      auth.PP.Q.String(),
		G:      auth.PP.G.String(),
		Vec:    vec,
	}

	// Send JSON to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
