package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		values    [][]byte
		expRoot   string
		expLeaves []string
		err       error
	}{
		{
			name:   "No values should fail",
			values: [][]byte{},
			err:    ErrNoLeaves,
		},
		{
			name:      "One leaf should succeed",
			values:    [][]byte{[]byte("yolo")},
			expRoot:   "311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02",
			expLeaves: []string{"311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02"},
		},
		{
			name:    "Two values should succeed",
			values:  [][]byte{[]byte("yolo"), []byte("diftp")},
			expRoot: "a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b",
			expLeaves: []string{
				"311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02",
				"4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd",
			},
		},
		{
			name:    "Three values should succeed",
			values:  [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			expRoot: "c015cc9ef945a1aa2e3936249b45eeeccb80a4ab1b87aebefcd0f9844d857b84",
			expLeaves: []string{
				"311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02",
				"4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd",
				"69d65b9a363d4ca7b25cdaff49ad682c2f42fa51cc765f56b2c6a2a89d038a21",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.Equal(t, tc.expRoot, hex.EncodeToString(tree.Root.Hash), "Tree root mismatch")

				for i, leaf := range tree.Leaves {
					assert.Equal(t, tc.expLeaves[i], hex.EncodeToString(leaf.Hash))
				}
			}
		})
	}
}

func TestUpdateLeaf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		values   [][]byte
		index    int
		newValue []byte
		err      error
	}{
		{
			name:     "Update first leaf",
			values:   [][]byte{[]byte("leaf1"), []byte("leaf2")},
			index:    0,
			newValue: []byte("updatedLeaf1"),
		},
		{
			name:     "Update second leaf",
			values:   [][]byte{[]byte("leaf1"), []byte("leaf2")},
			index:    1,
			newValue: []byte("updatedLeaf2"),
		},
		{
			name:     "Update invalid index",
			values:   [][]byte{[]byte("leaf1"), []byte("leaf2")},
			index:    3,
			newValue: []byte("invalidLeaf"),
			err:      ErrIndexOutOfBounds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)
			require.NoError(t, err)

			err = tree.UpdateLeaf(tc.index, tc.newValue)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err, "Expected error")
			} else {
				require.NoError(t, err, "No error expected for valid update")
				assert.Equal(t, tc.newValue, tree.Leaves[tc.index].Value)
			}
		})
	}
}

func TestRemoveLeaf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		initial    [][]byte
		removeIdx  int
		expLeafLen int
		err        error
	}{
		{
			name:       "Remove first leaf",
			initial:    [][]byte{[]byte("leaf1"), []byte("leaf2")},
			removeIdx:  0,
			expLeafLen: 1,
		},
		{
			name:       "Remove second leaf",
			initial:    [][]byte{[]byte("leaf1"), []byte("leaf2")},
			removeIdx:  1,
			expLeafLen: 1,
		},
		{
			name:       "Remove only leaf",
			initial:    [][]byte{[]byte("leaf1")},
			removeIdx:  0,
			expLeafLen: 0,
		},
		{
			name:       "Remove invalid index",
			initial:    [][]byte{[]byte("leaf1"), []byte("leaf2")},
			removeIdx:  2,
			expLeafLen: 2,
			err:        ErrIndexOutOfBounds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hashFunc := sha256.New
			tree, err := NewTree(tc.initial, hashFunc)
			require.NoError(t, err)

			var oldVal *Node
			if !errors.Is(tc.err, ErrIndexOutOfBounds) {
				oldVal = tree.Leaves[tc.removeIdx]
			}

			err = tree.RemoveLeaf(tc.removeIdx)
			if tc.err != nil {
				assert.ErrorIs(t, tc.err, err, "Expected error")
			} else {
				require.NoError(t, err, "No error expected for valid removal")
				if tc.expLeafLen > 0 && tc.removeIdx < len(tree.Leaves)-1 {
					assert.NotEqual(t, oldVal, tree.Leaves[tc.removeIdx])
				}
				assert.Len(t, tree.Leaves, tc.expLeafLen, "Leaf count should match expected count after removal")
			}
		})
	}
}

func TestGenerateProof(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		values     [][]byte
		proofValue []byte
		err        error
		expProof   Proof
	}{
		{
			name:       "Single leaf, valid proof",
			values:     [][]byte{[]byte("yolo")},
			proofValue: []byte("yolo"),
			expProof: Proof{
				Hashes: [][]byte{},
				Index:  0,
			},
		},
		{
			name:       "Two leaves, valid proof for first leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("yolo"),
			expProof: func() Proof {
				siblingHash := sha256.Sum256([]byte("diftp"))
				return Proof{
					Hashes: [][]byte{siblingHash[:]},
					Index:  0,
				}
			}(),
		},
		{
			name:       "Two leaves, valid proof for second leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("diftp"),
			expProof: func() Proof {
				siblingHash := sha256.Sum256([]byte("yolo"))
				return Proof{
					Hashes: [][]byte{siblingHash[:]},
					Index:  1,
				}
			}(),
		},
		{
			name:       "Three leaves, valid proof for middle leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("diftp"),
			expProof: func() Proof {
				// First sibling hash: Hash of "yolo"
				siblingHashL1 := sha256.Sum256([]byte("yolo"))

				// Second sibling hash: Hash of "ngmi" (leaf on the right)
				siblingHashL2 := sha256.Sum256([]byte("ngmi"))

				return Proof{
					// Both sibling hashes are needed
					Hashes: [][]byte{siblingHashL1[:], siblingHashL2[:]},
					Index:  1, // Index for "diftp" is 1
				}
			}(),
		},
		{
			name:       "Three leaves, invalid proof for non-existent leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("nonexistent"),
			expProof: Proof{
				Hashes: [][]byte{
					[]byte("gibberishhash1"),
					[]byte("gibberishhash2"),
				},
				Index: 42,
			},
			err: ErrNoVal,
		},
		{
			name:       "Five leaves, valid proof for third leaf",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("c"),
			expProof: Proof{
				Hashes: func() [][]byte {
					siblingHashL4 := sha256.Sum256([]byte("d"))

					hashL1 := sha256.Sum256([]byte("a"))
					hashL2 := sha256.Sum256([]byte("b"))
					hashL12 := combineHashes(hashL1[:], hashL2[:], sha256.New())

					hashL5 := sha256.Sum256([]byte("e"))

					return [][]byte{siblingHashL4[:], hashL12, hashL5[:]}
				}(),
				Index: 2,
			},
		},
		{
			name:       "Five leaves, empty proof",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("f"),
			err:        ErrNoVal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)
			require.NoError(t, err)

			proof, err := tree.GenerateProof(tc.proofValue)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err, "Expected error")
			} else {
				require.NoError(t, err, "No error expected for generating proof")

				require.Equal(t, len(tc.expProof.Hashes), len(proof.Hashes))
				for i, hash := range tc.expProof.Hashes {
					assert.Equal(t, hash, proof.Hashes[i])
				}
				assert.Equal(t, tc.expProof.Index, proof.Index)
			}
		})
	}
}

func TestVerifyProof(t *testing.T) {
	tests := []struct {
		name    string
		values  [][]byte
		proof   Proof
		val     []byte
		err     error
		isValid bool
	}{
		{
			name:   "Single leaf, valid proof",
			values: [][]byte{[]byte("yolo")},
			proof: Proof{
				Hashes: [][]byte{},
				Index:  0,
			},
			val:     []byte("yolo"),
			isValid: true,
		},
		{
			name:   "Two leaves, valid proof for first leaf",
			values: [][]byte{[]byte("yolo"), []byte("diftp")},
			proof: func() Proof {
				siblingHash := sha256.Sum256([]byte("diftp"))
				return Proof{
					Hashes: [][]byte{siblingHash[:]},
					Index:  0,
				}
			}(),
			val:     []byte("yolo"),
			isValid: true,
		},
		{
			name:   "Two leaves, valid proof for second leaf",
			values: [][]byte{[]byte("yolo"), []byte("diftp")},
			proof: func() Proof {
				siblingHash := sha256.Sum256([]byte("yolo"))
				return Proof{
					Hashes: [][]byte{siblingHash[:]},
					Index:  1,
				}
			}(),
			val:     []byte("diftp"),
			isValid: true,
		},
		{
			name:   "Three leaves, valid proof for middle leaf",
			values: [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proof: func() Proof {
				firstSiblingHash := sha256.Sum256([]byte("yolo"))
				secondSiblingHash := sha256.Sum256([]byte("ngmi"))
				return Proof{
					Hashes: [][]byte{firstSiblingHash[:], secondSiblingHash[:]},
					Index:  1,
				}
			}(),
			val:     []byte("diftp"),
			isValid: true,
		},
		{
			name:   "Three leaves, invalid proof for non-existent leaf",
			values: [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proof: func() Proof {
				firstSiblingHash := sha256.Sum256([]byte("yolo"))
				secondSiblingHash := sha256.Sum256([]byte("ngmi"))
				return Proof{
					Hashes: [][]byte{firstSiblingHash[:], secondSiblingHash[:]},
					Index:  1,
				}
			}(),
			val:     []byte("nonexistant"),
			err:     ErrProofVerificationFailed,
			isValid: false,
		},
		{
			name:   "Five leaves, valid proof for third leaf",
			values: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proof: func() Proof {
				// Sibling hash for leaf "c" is "d"
				siblingHashL4 := sha256.Sum256([]byte("d"))

				// Hash of L1 ("a") and L2 ("b")
				hashL1 := sha256.Sum256([]byte("a"))
				hashL2 := sha256.Sum256([]byte("b"))
				hashL12 := combineHashes(hashL1[:], hashL2[:], sha256.New())

				// Hash of L5 ("e") — the sibling of the parent of L3 and L4
				siblingHashL5 := sha256.Sum256([]byte("e"))

				return Proof{
					// First combine "c" with "d", then with "e", and finally with combined L1+L2
					Hashes: [][]byte{siblingHashL4[:], hashL12, siblingHashL5[:]},
					Index:  2, // Index for "c" is 2 (even)
				}
			}(),
			val:     []byte("c"),
			isValid: true,
		},
		{
			name:   "Five leaves, invalid proof for non-existent leaf",
			values: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proof: func() Proof {
				// Sibling hash for leaf "c" is "d"
				siblingHashL4 := sha256.Sum256([]byte("d"))

				// Hash of L1 ("a") and L2 ("b")
				hashL1 := sha256.Sum256([]byte("a"))
				hashL2 := sha256.Sum256([]byte("b"))
				hashL12 := combineHashes(hashL1[:], hashL2[:], sha256.New())

				// Hash of L5 ("e") — the sibling of the parent of L3 and L4
				siblingHashL5 := sha256.Sum256([]byte("e"))

				return Proof{
					// First combine "c" with "d", then with "e", and finally with combined L1+L2
					Hashes: [][]byte{siblingHashL4[:], hashL12, siblingHashL5[:]},
					Index:  2, // Index for "c" is 2 (even)
				}
			}(),
			val:     []byte("f"),
			isValid: false,
			err:     ErrProofVerificationFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			//t.Parallel()

			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)
			require.NoError(t, err)

			isValid, err := tree.VerifyProof(&tc.proof, tc.val)
			assert.ErrorIs(t, err, tc.err)
			assert.Equal(t, tc.isValid, isValid, "Proof should be valid")
		})
	}
}

func TestGenerateVerifyProof(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		values     [][]byte
		proofValue []byte
		err        error
	}{
		{
			name:       "Single leaf, valid proof",
			values:     [][]byte{[]byte("yolo")},
			proofValue: []byte("yolo"),
		},
		{
			name:       "Two leaves, valid proof for first leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("yolo"),
		},
		{
			name:       "Two leaves, valid proof for second leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("diftp"),
		},
		{
			name:       "Three leaves, valid proof for middle leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("diftp"),
		},
		{
			name:       "Three leaves, invalid proof for non-existent leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("nonexistent"),
			err:        ErrNoVal,
		},
		{
			name:       "Five leaves, valid proof for third leaf",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("c"),
		},
		{
			name:       "Five leaves, invalid proof for non-existent leaf",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("f"),
			err:        ErrNoVal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)
			require.NoError(t, err)

			proof, err := tree.GenerateProof(tc.proofValue)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err, "Expected error")
			} else {
				require.NoError(t, err, "No error expected for generating proof")
				isValid, err := tree.VerifyProof(proof, tc.proofValue)
				assert.NoError(t, err)
				assert.True(t, isValid, "Proof should be valid")
			}
		})
	}
}

func TestCombineHashes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		index       int
		currentHash []byte
		siblingHash []byte
		expected    string
	}{
		{
			name:  "Combine when current node is on the left (even index)",
			index: 0,
			currentHash: func() []byte {
				hash := sha256.Sum256([]byte("yolo"))
				return hash[:]
			}(),
			siblingHash: func() []byte {
				hash := sha256.Sum256([]byte("diftp"))
				return hash[:]
			}(),
			expected: "a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b",
		},
		{
			name:  "Combine when current node is on the right (odd index)",
			index: 0,
			currentHash: func() []byte {
				hash := sha256.Sum256([]byte("diftp"))
				return hash[:]
			}(),
			siblingHash: func() []byte {
				hash := sha256.Sum256([]byte("yolo"))
				return hash[:]
			}(),
			expected: "6d1a5ee206c0e2b5d4a69176d1873f6b84a51a593f36e92feaab586c2646e22e",
		},
		{
			name:        "Empty current hash",
			index:       0,
			currentHash: []byte{},
			siblingHash: func() []byte {
				hash := sha256.Sum256([]byte("diftp"))
				return hash[:]
			}(),
			expected: "4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd",
		},
		{
			name:  "Empty sibling hash",
			index: 0,
			currentHash: func() []byte {
				hash := sha256.Sum256([]byte("diftp"))
				return hash[:]
			}(),
			siblingHash: []byte{},
			expected:    "4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			result := combineHashes(tc.currentHash, tc.siblingHash, hashFunc)

			assert.Equal(t, tc.expected, hex.EncodeToString(result))
		})
	}
}

func TestStringifyTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values [][]byte
		exp    string
	}{
		{
			name:   "Single leaf",
			values: [][]byte{[]byte("yolo")},
			exp: `311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02
    (Leaf Value: yolo)
`,
		},
		{
			name:   "Two values",
			values: [][]byte{[]byte("yolo"), []byte("diftp")},
			exp: `a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b
    ├── 311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02
        (Leaf Value: yolo)
    └── 4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd
        (Leaf Value: diftp)
`,
		},
		{
			name:   "Three values",
			values: [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			exp: `c015cc9ef945a1aa2e3936249b45eeeccb80a4ab1b87aebefcd0f9844d857b84
    ├── a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b
    │   ├── 311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02
    │       (Leaf Value: yolo)
    │   └── 4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd
    │       (Leaf Value: diftp)
    └── 69d65b9a363d4ca7b25cdaff49ad682c2f42fa51cc765f56b2c6a2a89d038a21
        (Leaf Value: ngmi)
`,
		},
		{
			name:   "Five values",
			values: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			exp: `d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba
    ├── 14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7
    │   ├── e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a
    │   │   ├── ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
    │   │       (Leaf Value: a)
    │   │   └── 3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
    │   │       (Leaf Value: b)
    │   └── bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b
    │       ├── 2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6
    │           (Leaf Value: c)
    │       └── 18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4
    │           (Leaf Value: d)
    └── 3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea
        (Leaf Value: e)
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New
			tree, err := NewTree(tc.values, hashFunc)
			require.NoError(t, err)

			treeStr := tree.Root.StringifyTree("", false)
			assert.Equal(t, tc.exp, treeStr)
		})
	}
}

func BenchmarkTreeConstruction(b *testing.B) {
	for _, size := range []int{1024, 16384, 131072} {
		b.Run(fmt.Sprintf("%d leaves", size), func(b *testing.B) {
			data := generateDummyData(size)
			hashFunc := sha256.New
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := NewTree(data, hashFunc)
				if err != nil {
					b.Errorf("Error creating Merkle tree: %v", err)
				}
			}
		})
	}
}

func BenchmarkProofGeneration(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("%d leaves", size), func(b *testing.B) {
			data := generateDummyData(size)
			hashFunc := sha256.New
			tree, _ := NewTree(data, hashFunc)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = tree.GenerateProof(data[size/2])
			}
		})
	}
}

func BenchmarkProofVerification(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("%d leaves", size), func(b *testing.B) {
			data := generateDummyData(size)
			hashFunc := sha256.New
			tree, _ := NewTree(data, hashFunc)
			proof, _ := tree.GenerateProof(data[size/2])
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = tree.VerifyProof(proof, data[size/2])
			}
		})
	}
}

func generateDummyData(size int) [][]byte {
	data := make([][]byte, size)
	for i := 0; i < size; i++ {
		// Create a fixed size [32]byte and convert it to a slice
		// to align benchmarks
		var fixedSizeArray [32]byte
		copy(fixedSizeArray[:], []byte(fmt.Sprintf("leaf-%d", i)))
		data[i] = fixedSizeArray[:]
	}
	return data
}
