# Anamorphic E-Voting System

## Description

This repository contains an electronic voting system that uses anamorphic encryption to mitigate vote buying. The system demonstrates how cryptographic techniques can enhance election security.

## Notes

1. Simplified electronic voting system for research and benchmarking
2. Uses ElGamal anamorphic encryption to secure votes.
3. Supports authority, vote collector (VC), voters/users, and an optional "evil entity" for simulating the vote coercion situation.

## Requirements
- Go 1.20+ (or compatible version installed on your system)

Check your Go version with:

    go version

## Running the system

### 1. Start the Server

The server sets up the system, generates keys for the authority, and creates the candidate list (default: 20 candidates - 15 "good" and 5 "evil").

    go run .\server

### 2. Initialize the Vote Collector (VC)

The VC handles vote collection. Running this generates VC keys via the authority.

    go run .\vc

### 3. Add Users / Voters

Each user must be registered in the system. Keys are generated for the user by the authority, and the VC receives the necessary user information.

    go run .\client <userID>

The system waits for 10 users by default. Once all users are registered, the voting phases execute automatically, and the VC computes the results. 

### 4. Optional: Run Evil Entity 

The evil entity simulates an adversary who can attempt to access votes. Only fake votes can be decrypted from confirmations in this scenario.

    go run .\evil

- Generates keys for evil entity via authority
- Receives the user list and can fetch certain votes (limited to fake votes because the use of anamorphic encryption)