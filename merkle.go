package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
	"sync"
)

var (
	ErrNoLeaves         = errors.New("cannot create a tree with no leaves")
	ErrNoVal            = errors.New("value not found in the tree")
	ErrIndexOutOfBounds = fmt.Errorf("index out of bounds")
)

// Node represents a node in the Merkle tree
type Node struct {
	Hash  []byte
	Value []byte
	Left  *Node
	Right *Node
}

func NewNode(hash, val []byte) *Node {
	return &Node{Hash: hash, Value: val}
}

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root     *Node
	HashPool *sync.Pool
	Leaves   []*Node
}

// NewMerkleTree creates a new Merkle tree from the given values and hash function.
func NewMerkleTree(values [][]byte, hashPool *sync.Pool) (*MerkleTree, error) {
	if len(values) == 0 {
		return nil, ErrNoLeaves
	}

	hasher := hashPool.Get().(hash.Hash)
	defer hashPool.Put(hasher)

	// Convert leaves into Nodes
	var nodes []*Node
	for _, val := range values {
		hasher.Write(val)
		hashedValue := hasher.Sum(nil)
		node := NewNode(hashedValue, val)
		nodes = append(nodes, node)
		hasher.Reset()
	}

	tree := &MerkleTree{
		HashPool: hashPool,
	}
	tree.Root = buildTree(nodes, hashPool)
	tree.Leaves = nodes

	return tree, nil
}

func buildTree(nodes []*Node, hashPool *sync.Pool) *Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	numParentNodes := (len(nodes) + 1) / 2
	parents := make([]*Node, numParentNodes)

	var wg sync.WaitGroup
	wg.Add(numParentNodes)

	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *Node
		if i+1 < len(nodes) {
			right = nodes[i+1]
		}

		go func(i int, left, right *Node) {
			defer wg.Done()

			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()

			// Hash children to create parent hash
			hasher.Write(left.Hash)
			if right != nil {
				hasher.Write(right.Hash)
			}
			parentHash := hasher.Sum(nil)

			parents[i/2] = &Node{Hash: parentHash, Left: left, Right: right}
		}(i, left, right)
	}

	wg.Wait()

	return buildTree(parents, hashPool)
}

// AddLeaf adds a new lead to the Merkle tree and recalculates
// the tree.
func (m *MerkleTree) AddLeaf(value []byte) {
	hasher := m.HashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		m.HashPool.Put(hasher)
	}()

	hasher.Write(value)
	leaf := NewNode(hasher.Sum(nil), value)

	m.Leaves = append(m.Leaves, leaf)
	m.Root = buildTree(m.Leaves, m.HashPool)
}

// UpdateLeaf updates the value of the leaf at the given index
// and recalculates the tree.
func (m *MerkleTree) UpdateLeaf(index int, newVal []byte) error {
	if index < 0 || index >= len(m.Leaves) {
		return ErrIndexOutOfBounds
	}

	hasher := m.HashPool.Get().(hash.Hash)
	leaf := m.Leaves[index]
	hasher.Write(newVal)
	leaf.Hash = hasher.Sum(nil)
	hasher.Reset()
	leaf.Value = newVal

	m.updateParentHashes(leaf)
	return nil
}

// updateParentHashes propagates changes upwards to the root
// after a leaf has been updated.
func (m *MerkleTree) updateParentHashes(leaf *Node) {
	current := leaf
	parent := findParent(m.Root, current)

	hasher := m.HashPool.Get().(hash.Hash)
	for parent != nil {
		if parent.Left != nil {
			hasher.Write(parent.Left.Hash)
		}
		if parent.Right != nil {
			hasher.Write(parent.Right.Hash)
		}
		parent.Hash = hasher.Sum(nil)
		hasher.Reset()

		// Move up the tree
		current = parent
		parent = findParent(m.Root, current)
	}
}

// RemoveLeaf removes a leaf at a given index
// and recalculates the tree.
func (m *MerkleTree) RemoveLeaf(index int) error {
	if index < 0 || index >= len(m.Leaves) {
		return ErrIndexOutOfBounds
	}

	m.Leaves = slices.Delete(m.Leaves, index, index+1)
	m.Root = buildTree(m.Leaves, m.HashPool)
	return nil
}

// Proof represents the hash chain from a leaf to the root
// to prove that a leaf is part of the tree.
type Proof struct {
	Hashes [][]byte
	Index  int
}

// GenerateProof generates an inclucion proof for a given value.
func (m *MerkleTree) GenerateProof(value []byte) (*Proof, error) {
	return m.traverseForProof(m.Root, value, 0)
}

// traverseForProof dynamically traverses the tree to find the leaf and construct the proof
func (m *MerkleTree) traverseForProof(node *Node, value []byte, index int) (*Proof, error) {
	if node == nil {
		return nil, ErrNoVal
	}

	if string(node.Value) == string(value) {
		return m.buildProof(node, index), nil
	}

	// Recursively search the left and right children
	if proof, err := m.traverseForProof(node.Left, value, index*2); err == nil {
		return proof, nil
	}
	return m.traverseForProof(node.Right, value, index*2+1)
}

// buildproof constructs the proof of inclucion from the leaf to the root.
func (m *MerkleTree) buildProof(node *Node, index int) *Proof {
	var hashes [][]byte
	current := node

	for current != nil {
		siblingHash := []byte{}
		parent := findParent(m.Root, current)

		// Get sibling hash
		if parent != nil {
			if parent.Left == current {
				if parent.Right != nil {
					siblingHash = parent.Right.Hash
				}
			} else {
				if parent.Left != nil {
					siblingHash = parent.Left.Hash
				}
			}
			hashes = append(hashes, siblingHash)
		}

		// Move up the tree
		current = parent
	}

	return &Proof{
		Hashes: hashes,
		Index:  index,
	}
}

// findParent traverses the tree to find the parent of a given node.
func findParent(root, node *Node) *Node {
	if root == nil || root == node {
		return nil
	}

	// Check if either left or right child is the target node
	if root.Left == node || root.Right == node {
		return root
	}

	// Recursively check the left and right children
	if parent := findParent(root.Left, node); parent != nil {
		return parent
	}
	return findParent(root.Right, node)
}

// VerifyProof returns true if the proof is verified.
func (m *MerkleTree) VerifyProof(proof *Proof, value []byte) bool {
	// Start by hashing the leaf value
	hasher := m.HashPool.Get().(hash.Hash)
	hasher.Write(value)
	currentHash := hasher.Sum(nil)
	hasher.Reset()

	for _, siblingHash := range proof.Hashes {
		currentHash = combineHashes(proof.Index, currentHash, siblingHash, m.HashPool)
		// Move up to the next level, adjust the index accordingly
		proof.Index /= 2
	}

	// Compare the final calculated root hash with the actual root hash
	return string(currentHash) == string(m.Root.Hash)
}

// combineHashes combines the current and sibling hashes based on the index.
func combineHashes(index int, currentHash, siblingHash []byte, hashPool *sync.Pool) []byte {
	hasher := hashPool.Get().(hash.Hash)
	defer hashPool.Put(hasher)
	// Combine currentHash and siblingHash based on the index
	// The index determines if the current node is on the left or right
	if index%2 == 0 {
		// If the index is even, the current node is on the left
		hasher.Write(currentHash)
		hasher.Write(siblingHash)
	} else {
		// If the index is odd, the current node is on the right
		hasher.Write(siblingHash)
		hasher.Write(currentHash)
	}
	hash := hasher.Sum(nil)
	hasher.Reset()
	return hash
}

func (m *MerkleTree) PrintTree() {
	if m.Root == nil {
		fmt.Println("Empty tree")
	} else {
		fmt.Print(m.Root.StringifyTree("", false))
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
		result.WriteString(fmt.Sprintf("%s\n", hex.EncodeToString(n.Hash)))
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
