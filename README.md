# Anamorphic E-Voting System

## Description

This repository contains an electronic voting system that uses anamorphic encryption to mitigate vote buying. The system demonstrates how cryptographic techniques can enhance election security.

---

## Notes

1. Simplified electronic voting system for research and benchmarking
2. Uses ElGamal anamorphic encryption to secure votes.
3. Supports authority, vote collector (VC), voters/users, and an optional "evil entity" for simulating the vote coercion situation.

---

## Requirements
- Go 1.20+ (or compatible version installed on your system)

Check your Go version with:

    go version

---

## Running the system

### 1. Start the Server

The server sets up the system, generates keys for the authority, and creates the candidate list (default: 20 candidates - 15 "good" and 5 "evil").

    go run .\server

---

### 2. Initialize the Vote Collector (VC)

The VC handles vote collection. Running this generates VC keys via the authority.

    go run .\vc


---

### 3. Add Users / Voters

Each user must be registered in the system. Keys are generated for the user by the authority, and the VC receives the necessary user information.

    go run .\client <userID>

The system waits for 10 users by default. Once all users are registered, the voting phases execute automatically, and the VC computes the results. 

---

### 4. Optional: Run Evil Entity 

The evil entity simulates an adversary who can attempt to access votes. Only fake votes can be decrypted from confirmations in this scenario.

    go run .\evil

- Generates keys for evil entity via authority
- Receives the user list and can fetch certain votes (limited to fake votes because the use of anamorphic encryption)

---

## Benchmarking the system

All benchmarks use:

    go test -bench=<Name> -benchmem

Each benchmark reports:
- Latency (ns/op)
- Heap memory usage (B/op)
- Memory allocations (alloc/op)

Some benchmarks require that the server or VC be running beforehand. These are noted below. 

---

### Important Note on Benchmark Types

**Benchmarks that do ***not*** require the server or VC to be running only simulate the internal logic of the system.**
They **do not perform real HTTP requests** between Authority, VC, and User. These benchmarks measure only the cryptographic and computational operationg that the entities would perform internally.

Benchmarks that *do* require the server or VC to be running include actula HTTP interactions and therefore reflect the real end-to-end workflow. 

---

### 1. Authority Benchmarks

#### Authority Setup (Simulated)

    cd server
    go test -bench=AuthoritySetup -benchmem

Measures: Key generation for authority and creation of the candidate group (20 candidates).

---

### 2. VC Benchmarks

#### VC Setup (Requires server running)

Start server:
    
    cd server
    go run .

Run benchmark: 

    cd vc
    go test -bench=VCRegistration -benchmem

Measures: VC key generation (apk, ask, dk).

---

#### VC Setup Voting Group (Simulated)

    cd vc
    go test -bench=SetupVotingGroupRealParams -benchmem

Measures: Generating and distributing random values to users, sending shares and VC's double key (anamorphically encrypted). *Note: Total time covers all 10 users.*

---

#### VC Receive Vote (Simulated)

    cd vc
    go test -bench=VCSaveVote -benchmem

Measures: Decrypting user's anamorphic ciphertext, computing vi, storing vote, and re-encryting vf and vi for the user confirmation.

---

#### VC Compute Result (Requires server running)

Start server:

    cd server
    go run .

Run benchmark: 

    cd vc
    go test -bench=VCComputeResult -benchmem

Measures: Retrieving candidate list and computing the final tally.

### 3. User Benchmarks

#### User Registration (Requires server + VC running)

Start server:

    cd server
    go run .

Setup VC:

    cd vc
    go run .

Run benchmarks:

    cd client
    go test -bench=UserReg -benchmem

Measures: User key generation (apk, ask, dk) and sending registration data to VC.

---

#### User Generate + Send Vote (Simulated)

    cd client
    go test -bench=UserVote -benchmem

Measures: Decrypting shares + VC double key, computing blind vote, sending anamorphic ciphertext (vf, bi).

---

#### User Receive Confirmation (Simulated)

    cd client
    go test -bench=UserConfirm -benchmem

Measures: Decrypting VC confirmation and verifying vf and vi. 

---

### 4. Evil Entity Benchmarks

#### Evil Entity: User's Fake Vote
(Requires server + VC running + registered and vote-casted users)

Start server:

    cd server
    go run .

Setup VC:

    cd vc
    go run .    

At least 10 registered users:

    cd client
    go run . <userID>   # repeat until 10 users exist

Benchmark (after waiting for all users to cast their votes):

    cd evil
    go test -bench=EvilCheck -benchmem

Measures: Fetching and decrypting user confirmation to extract fake vote. 

---