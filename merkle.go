package merkle

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"
)

var (
	ErrNoLeaves                = errors.New("cannot create a tree with no leaves")
	ErrNoVal                   = errors.New("value not found in the tree")
	ErrIndexOutOfBounds        = errors.New("index out of bounds")
	ErrProofVerificationFailed = errors.New("proof verification failed")
)

// Node represents a node in the Merkle tree
type Node struct {
	Left   *Node
	Right  *Node
	Parent *Node
	Hash   []byte
	Value  []byte
}

func NewNode(hash, val []byte) *Node {
	return &Node{Hash: hash, Value: val}
}

// Tree represents a Merkle tree
type Tree struct {
	Root     *Node
	HashFunc hash.Hash
	Leaves   []*Node
}

// NewTree creates a new Merkle tree from the given values and hash function.
func NewTree(values [][]byte, newHashFunc func() hash.Hash) (*Tree, error) {
	if len(values) == 0 {
		return nil, ErrNoLeaves
	}

	preHashedLeaves := preHashLeaves(values, newHashFunc)

	// Convert leaves into Nodes
	nodes := make([]*Node, len(preHashedLeaves))
	for i, hash := range preHashedLeaves {
		node := NewNode(hash, values[i])
		nodes[i] = node
	}

	hashFunc := newHashFunc()

	tree := &Tree{
		HashFunc: hashFunc,
	}
	tree.Root = buildTree(nodes, hashFunc)
	tree.Leaves = nodes

	return tree, nil
}

// preHashLeaves prehashes the values
func preHashLeaves(values [][]byte, newHashFunc func() hash.Hash) [][]byte {
	preHashedLeaves := make([][]byte, len(values))

	numWorkers := runtime.NumCPU()
	if len(values) < numWorkers {
		numWorkers = len(values)
	}

	var g errgroup.Group
	g.SetLimit(numWorkers)

	// Compute batch size using integer division
	// and handle remaining values.
	batchSize := len(values) / numWorkers
	remainder := len(values) % numWorkers

	for i := 0; i < numWorkers; i++ {
		start := i * batchSize
		end := start + batchSize

		// Add remaining values to the last batch
		if i == numWorkers-1 {
			end += remainder
		}

		g.Go(func() error {
			hasher := newHashFunc()
			for j := start; j < end; j++ {
				hasher.Reset()
				hasher.Write(values[j])
				preHashedLeaves[j] = hasher.Sum(nil)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		panic(err)
	}

	return preHashedLeaves
}

func buildTree(nodes []*Node, hashFunc hash.Hash) *Node {
	if len(nodes) == 0 {
		return nil
	}
	for len(nodes) > 1 {
		parents := make([]*Node, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			if i+1 < len(nodes) {
				right := nodes[i+1]

				// Hash the left and right node hashes
				hashFunc.Reset()
				hashFunc.Write(left.Hash)
				hashFunc.Write(right.Hash)
				parentHash := hashFunc.Sum(nil)

				parentNode := &Node{
					Hash:  parentHash,
					Left:  left,
					Right: right,
				}

				left.Parent = parentNode
				right.Parent = parentNode

				parents[i/2] = parentNode
			} else {
				// If right is nil, carry the left node up without hashing
				parents[i/2] = left
			}
		}
		nodes = parents
	}
	return nodes[0]
}

// UpdateLeaf updates the value of the leaf at the given index
// and recalculates the tree.
func (t *Tree) UpdateLeaf(index int, newVal []byte) error {
	if index < 0 || index >= len(t.Leaves) {
		return ErrIndexOutOfBounds
	}

	leaf := t.Leaves[index]
	t.HashFunc.Reset()
	t.HashFunc.Write(newVal)
	leaf.Hash = t.HashFunc.Sum(nil)
	leaf.Value = newVal

	t.updateParentHashes(leaf)
	return nil
}

// updateParentHashes propagates changes upwards to the root
// after a leaf has been updated.
func (t *Tree) updateParentHashes(leaf *Node) {
	current := leaf
	for current.Parent != nil {
		parent := current.Parent
		t.HashFunc.Reset()
		if parent.Left != nil {
			t.HashFunc.Write(parent.Left.Hash)
		}
		if parent.Right != nil {
			t.HashFunc.Write(parent.Right.Hash)
		}
		parent.Hash = t.HashFunc.Sum(nil)
		current = parent
	}
}

// RemoveLeaf removes a leaf at a given index
// and recalculates the tree.
func (t *Tree) RemoveLeaf(index int) error {
	if index < 0 || index >= len(t.Leaves) {
		return ErrIndexOutOfBounds
	}

	leafToRemove := t.Leaves[index]
	t.Leaves = slices.Delete(t.Leaves, index, index+1)
	parent := leafToRemove.Parent

	// If there are no leaves left, the tree is now empty
	if len(t.Leaves) == 0 && parent == nil {
		t.Root = nil
		return nil
	}

	// Remove leaf ref from parent
	if parent.Left == leafToRemove {
		parent.Left = nil
	} else if parent.Right == leafToRemove {
		parent.Right = nil
	}

	// Traverse tree upwards and update hashes
	t.updateParentHashesAfterRemoval(parent)

	return nil
}

// updateParentHashesAfterRemoval traverses up the tree to update
// parent hashes after a leaf has been removed.
func (t *Tree) updateParentHashesAfterRemoval(node *Node) {
	current := node
	for current != nil {
		t.HashFunc.Reset()
		if current.Left != nil {
			// Only left child exists
			t.HashFunc.Write(current.Left.Hash)
		} else if current.Right != nil {
			// Only right child exists
			t.HashFunc.Write(current.Right.Hash)
		}
		current.Hash = t.HashFunc.Sum(nil)
		current = current.Parent
	}
}

// Proof represents the hash chain from a leaf to the root
// to prove that a leaf is part of the tree.
type Proof struct {
	Hashes [][]byte
	Index  int
}

// GenerateProof generates an inclucion proof for a given value.
func (t *Tree) GenerateProof(value []byte) (*Proof, error) {
	var leafIndex int
	found := false

	// Step 1: Find the leaf node that contains the given value.
	for i, leaf := range t.Leaves {
		if bytes.Equal(leaf.Value, value) {
			leafIndex = i
			found = true
			break
		}
	}

	// If the leaf is not found, return an error.
	if !found {
		return nil, ErrNoVal
	}

	// Step 2: Build the proof for the leaf at the given index.
	return t.GenerateProofByIndex(leafIndex)
}

// GenerateProofByIndex generates a proof for a leaf at the given index.
func (t *Tree) GenerateProofByIndex(index int) (*Proof, error) {
	if index < 0 || index >= len(t.Leaves) {
		return nil, ErrIndexOutOfBounds
	}

	leaf := t.Leaves[index]
	var hashes [][]byte

	// Traverse from the leaf to the root and collect sibling hashes.
	current := leaf
	for current.Parent != nil {
		var siblingHash []byte
		parent := current.Parent

		// Collect the sibling hash.
		if parent.Left == current {
			if parent.Right != nil {
				siblingHash = parent.Right.Hash
			}
		} else {
			if parent.Left != nil {
				siblingHash = parent.Left.Hash
			}
		}

		// Append the sibling hash to the proof.
		hashes = append(hashes, siblingHash)
		current = parent
	}

	// Step 3: Return the proof.
	return &Proof{
		Hashes: hashes,
		Index:  index,
	}, nil
}

// VerifyProof returns true if the proof is verified, otherwise false.
// It also returns an error if the verification process encounters an issue.
func (t *Tree) VerifyProof(proof *Proof, value []byte) (bool, error) {
	// Step 1: Hash the leaf value.
	t.HashFunc.Reset()
	t.HashFunc.Write(value)
	currentHash := t.HashFunc.Sum(nil)

	// Step 2: Traverse through the proof and compute the root hash.
	index := proof.Index
	for _, siblingHash := range proof.Hashes {
		if index%2 == 0 {
			// If the index is even, current node is on the left.
			currentHash = combineHashes(currentHash, siblingHash, t.HashFunc)
		} else {
			// If the index is odd, current node is on the right.
			currentHash = combineHashes(siblingHash, currentHash, t.HashFunc)
		}
		// Move up the tree by dividing index by 2.
		index /= 2
	}

	// Step 3: Compare the calculated root hash with the actual root hash.
	if !bytes.Equal(currentHash, t.Root.Hash) {
		return false, fmt.Errorf("%w: expected root %x, but got %x",
			ErrProofVerificationFailed, t.Root.Hash, currentHash)
	}

	// Step 4: Return true if the proof is valid.
	return true, nil
}

// combineHashes combines two hashes in the order they appear in the tree.
// If one of the hashes is empty, it combines only the non-empty hash.
func combineHashes(leftHash, rightHash []byte, hashFunc hash.Hash) []byte {
	hashFunc.Reset()

	// If leftHash is empty, just return the hash of the right one.
	if len(leftHash) == 0 {
		return rightHash
	}

	// If rightHash is empty, just return the hash of the left one.
	if len(rightHash) == 0 {
		return leftHash
	}

	// Otherwise, combine both hashes.
	hashFunc.Write(leftHash)
	hashFunc.Write(rightHash)
	return hashFunc.Sum(nil)
}

func (t *Tree) PrintTree() {
	if t.Root == nil {
		fmt.Println("Empty tree")
	} else {
		fmt.Print(t.Root.StringifyTree("", false))
	}
}

// StringifyTree creates an ASCII representations of the
// Merkle tree tha can be printed.
func (n *Node) StringifyTree(prefix string, isLeft bool) string {
	if n == nil {
		return ""
	}

	var result strings.Builder

	// Add current node (branch or leaf)
	if len(prefix) > 0 {
		if isLeft {
			result.WriteString(fmt.Sprintf("%s├── %s\n", prefix, hex.EncodeToString(n.Hash)))
		} else {
			result.WriteString(fmt.Sprintf("%s└── %s\n", prefix, hex.EncodeToString(n.Hash)))
		}
	} else {
		result.WriteString(hex.EncodeToString(n.Hash) + "\n")
	}

	// Recursively stringify left and right subtrees
	newPrefix := prefix
	if isLeft {
		newPrefix += "│   "
	} else {
		newPrefix += "    "
	}

	if n.Left != nil || n.Right != nil {
		if n.Left != nil {
			result.WriteString(n.Left.StringifyTree(newPrefix, true))
		}
		if n.Right != nil {
			result.WriteString(n.Right.StringifyTree(newPrefix, false))
		}
	} else if n.Value != nil {
		// Add leaf value without extra indentation
		result.WriteString(fmt.Sprintf("%s    (Leaf Value: %s)\n", prefix, string(n.Value)))
	}

	return result.String()
}
