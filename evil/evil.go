package main

import (
	"AnamorphicEVotingSystem/ElGamal"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
)

type Evil struct {
	Pk   *big.Int
	sk   *big.Int
	pp   ElGamal.Params
	Info []*UserInfo
}

type UserInfo struct {
	UserID string
	Port   int
}

var evil *Evil

const serverURL = "http://localhost:8080"

func main() {
	url := fmt.Sprintf("%s/register_evil", serverURL)
	resp, err := http.Get(url)

	if err != nil {
		log.Fatalf("Failed to contact authority: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Authority error: %s", body)
	}

	var data struct {
		Status string `json:"status"`
		Pk     string `json:"pk"`
		Sk     string `json:"sk"`
		P      string `json:"P"`
		Q      string `json:"Q"`
		G      string `json:"G"`
		Users  []struct {
			UserID string `json:"userID"`
			Port   int    `json:"port"`
		} `json:"users"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatalf("Invalid JSOn: %v", err)
	}

	P := new(big.Int)
	Q := new(big.Int)
	G := new(big.Int)
	P.SetString(data.P, 10)
	Q.SetString(data.Q, 10)
	G.SetString(data.G, 10)

	evil = &Evil{
		Pk:   new(big.Int),
		sk:   new(big.Int),
		pp:   ElGamal.Params{P: P, Q: Q, G: G},
		Info: make([]*UserInfo, 0),
	}

	for _, u := range data.Users {
		evil.Info = append(evil.Info, &UserInfo{
			UserID: u.UserID,
			Port:   u.Port,
		})
	}

	evil.Pk.SetString(data.Pk, 10)
	evil.sk.SetString(data.Sk, 10)

	fmt.Println("Now you have received all userinfo. Fetch confirmation from certain user. Select user from these users: ")
	for _, u := range evil.Info {
		fmt.Println("User", u.UserID)
	}

	fmt.Println("\nEnter userID to contact for confirmation:")

	var target string
	fmt.Print("> ")
	fmt.Scanln(&target)

	var selected *UserInfo

	for _, u := range evil.Info {
		if u.UserID == target {
			selected = u
			break
		}
	}

	if selected == nil {
		log.Fatalf("Invalid userID: %s", target)
	}

	urlConfirm := fmt.Sprintf("http://localhost:%d/confirm", selected.Port)
	fmt.Println("Contacting:", urlConfirm)

	payload := map[string]string{
		"pk_evil": evil.Pk.String(),
	}

	buf, _ := json.Marshal(payload)
	resp2, err := http.Post(urlConfirm, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		log.Fatalf("Failed to contact user %s: %v", selected.UserID, err)
	}
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)

	var respData struct {
		C0K    string `json:"c0k"`
		C1K    string `json:"c1k"`
		C0Conf string `json:"c0conf"`
		C1Conf string `json:"c1conf"`
	}

	if err := json.Unmarshal(body, &respData); err != nil {
		log.Fatalf("Failed to parse user response: %v", err)
	}

	c0k := new(big.Int)
	c1k := new(big.Int)
	c0k.SetString(respData.C0K, 10)
	c1k.SetString(respData.C1K, 10)

	c0conf := new(big.Int)
	c1conf := new(big.Int)
	c0conf.SetString(respData.C0Conf, 10)
	c1conf.SetString(respData.C1Conf, 10)

	skU := ElGamal.Dec(&evil.pp, evil.sk, c0k, c1k)
	vote := ElGamal.Dec(&evil.pp, skU, c0conf, c1conf)

	fmt.Println("User", target, "voted candidate number", vote)
}
