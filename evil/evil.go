package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
)

// Represents the malicious entity that can interact with users
type Evil struct {
	Pk   *big.Int
	sk   *big.Int
	pp   ElGamal.Params
	Info []*UserInfo
}

// Stores basic user info (ID and port for communication)
type UserInfo struct {
	UserID string
	Port   int
}

var evil *Evil

const serverURL = "http://localhost:8080"

// -------------------------------
// Initialization logic (once)
// -------------------------------

// Registers the malicious entity with the server and fetches users info
func RegisterEvil() error {
	// Call the server endpoint to register as an evil actor
	url := serverURL + "/register_evil"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Expected JSON response structure from server
	var data struct {
		Status string `json:"status"`
		Pk     string `json:"pk"` // Evil public key
		Sk     string `json:"sk"` // Evil secret key
		P      string `json:"P"`  // ElGamal parameters
		Q      string `json:"Q"`
		G      string `json:"G"`
		Users  []struct {
			UserID string `json:"userID"`
			Port   int    `json:"port"` // Port to communicate with user
		} `json:"users"`
	}

	// Decode the JSON response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	// Convert string parameters to big.Int
	P, _ := new(big.Int).SetString(data.P, 10)
	Q, _ := new(big.Int).SetString(data.Q, 10)
	G, _ := new(big.Int).SetString(data.G, 10)
	Pk := new(big.Int)
	Pk.SetString(data.Pk, 10)
	sk := new(big.Int)
	sk.SetString(data.Sk, 10)

	// Initialize the global evil struct
	evil = &Evil{
		Pk:   Pk,
		sk:   sk,
		pp:   ElGamal.Params{P: P, Q: Q, G: G},
		Info: []*UserInfo{},
	}

	// Store all registered users information
	for _, u := range data.Users {
		evil.Info = append(evil.Info, &UserInfo{
			UserID: u.UserID,
			Port:   u.Port,
		})
	}

	return nil
}

// -------------------------------
// Pick a random user
// -------------------------------

// Selects a random user from the list of registered users
func PickRandomUser() *UserInfo {
	return evil.Info[rand.Intn(len(evil.Info))]
}

// -------------------------------
// Perform the evil action for benchmarking
// -------------------------------

// Sends a malicious request to a given user and retrieves the decrypted vote
func EvilCheck(u *UserInfo) (*big.Int, error) {
	// COnstruct the endpoint to contact the user's listener
	urlConfirm := "http://localhost:" + strconv.Itoa(u.Port) + "/confirm"

	// Prepare payload containing the evil's public key
	payload := map[string]string{
		"pk_evil": evil.Pk.String(),
	}

	buf, _ := json.Marshal(payload)

	// Send POST request to user's /confirm endpoint
	resp, err := http.Post(urlConfirm, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the JSON response
	body, _ := io.ReadAll(resp.Body)

	var respData struct {
		C0K    string `json:"c0k"`
		C1K    string `json:"c1k"`
		C0Conf string `json:"c0conf"`
		C1Conf string `json:"c1conf"`
	}

	json.Unmarshal(body, &respData)

	// Convert strings to big.Int
	c0k := new(big.Int)
	c1k := new(big.Int)
	c0k.SetString(respData.C0K, 10)
	c1k.SetString(respData.C1K, 10)

	c0c := new(big.Int)
	c1c := new(big.Int)
	c0c.SetString(respData.C0Conf, 10)
	c1c.SetString(respData.C1Conf, 10)

	// Decrypt to retrieve user's ElGamal secret key
	skU := ElGamal.Dec(&evil.pp, evil.sk, c0k, c1k)

	// Decrypt vote
	vote := ElGamal.Dec(&evil.pp, skU, c0c, c1c)

	return vote, nil
}
