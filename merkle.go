package merkle

import (
	"encoding/hex"
	"errors"
	"hash"
)

var ErrNoLeaves = errors.New("cannot create a tree with no leaves")

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root       []byte
	ChildNodes [][]byte
	Leaves     [][]byte
	HashFunc   hash.Hash
}

// NewMerkleTree creates a new Merkle tree from the given leaves and hash function.
func NewMerkleTree(leaves [][]byte, hashFunc hash.Hash) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, ErrNoLeaves
	}

	tree := &MerkleTree{
		Leaves:   leaves,
		HashFunc: hashFunc,
	}

	tree.Root = tree.buildTree()

	return tree, nil
}

func (m *MerkleTree) buildTree() []byte {
	for _, child := range m.Leaves {
		m.HashFunc.Write(child)
	}
	return m.HashFunc.Sum(nil)
}

func (m *MerkleTree) PrintTree() {
	m.StringifyTree()
}

func (m *MerkleTree) StringifyTree() string {
	result := m.Root

	return hex.EncodeToString(result)
}
