package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/estensen/merkle"
)

func main() {
	// Example leaves
	leaves := [][]byte{
		[]byte("yolo"),
		[]byte("diftp"),
		[]byte("ngmi"),
		[]byte("lfg"),
	}

	// Create a Merkle tree with SHA-256
	tree, err := merkle.NewTree(leaves, sha256.New)
	if err != nil {
		panic(err)
	}

	tree.PrintTree()

	proofItem := []byte("diftp")
	proof, err := tree.GenerateProof(proofItem)
	if err != nil {
		panic(err)
	}

	isValid := tree.VerifyProof(proof, proofItem)
	if !isValid {
		fmt.Printf("%s is in the tree\n", proofItem)
	}
	fmt.Printf("%s is in the tree\n", proofItem)
}
