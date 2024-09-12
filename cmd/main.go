package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/estensen/merkle"
)

func main() {
	// Example leaves
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
	}

	// Initialize a Merkle tree with SHA-256
	hashFunc := sha256.New()
	tree, err := merkle.NewMerkleTree(leaves, hashFunc)
	if err != nil {
		fmt.Printf("Failed to create Merkle tree: %v\n", err)
		return
	}

	tree.PrintTree()

	proof, err := tree.GenerateProof([]byte("leaf1"))
	if err != nil {
		panic(err)
	}

	isValid := tree.VerifyProof(proof, []byte("leaf1"))
	if !isValid {
		panic("failed to verify proof for leaf1")
	} else {
		fmt.Println("leaf1 is in the tree")
	}
}
