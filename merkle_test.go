package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMerkleTree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		values  [][]byte
		expRoot string
		err     error
	}{
		{
			name:   "No values should fail",
			values: [][]byte{},
			err:    ErrNoLeaves,
		},
		{
			name:    "One leaf should succeed",
			values:  [][]byte{[]byte("yolo")},
			expRoot: "311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02",
		},
		{
			name:    "Two values should succeed",
			values:  [][]byte{[]byte("yolo"), []byte("diftp")},
			expRoot: "a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b",
		},
		{
			name:    "Three values should succeed",
			values:  [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			expRoot: "a86aafc816451783ed59106e681f937c23f20f8175c795600063a887dab1aca2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			tree, err := NewMerkleTree(tc.values, hashFunc)

			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.Equal(t, tc.expRoot, hex.EncodeToString(tree.Root.Hash), "Tree root should not be nil")
			}
		})
	}
}

func TestProofOfInclusion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		values     [][]byte
		proofValue []byte
		shouldPass bool
	}{
		{
			name:       "Single leaf, valid proof",
			values:     [][]byte{[]byte("yolo")},
			proofValue: []byte("yolo"),
			shouldPass: true,
		},
		{
			name:       "Two leaves, valid proof for first leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("yolo"),
			shouldPass: true,
		},
		{
			name:       "Two leaves, valid proof for second leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp")},
			proofValue: []byte("diftp"),
			shouldPass: true,
		},
		{
			name:       "Three leaves, valid proof for middle leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("diftp"),
			shouldPass: true,
		},
		{
			name:       "Three leaves, invalid proof for non-existent leaf",
			values:     [][]byte{[]byte("yolo"), []byte("diftp"), []byte("ngmi")},
			proofValue: []byte("nonexistent"),
			shouldPass: false,
		},
		{
			name:       "Five leaves, valid proof for third leaf",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("c"),
			shouldPass: true,
		},
		{
			name:       "Five leaves, invalid proof for non-existent leaf",
			values:     [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
			proofValue: []byte("f"),
			shouldPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			tree, err := NewMerkleTree(tc.values, hashFunc)
			assert.NoError(t, err)

			proof, err := tree.GenerateProof(tc.proofValue)
			if tc.shouldPass {
				assert.NoError(t, err)

				// Verify the proof
				isValid := tree.VerifyProof(proof, tc.proofValue)
				assert.True(t, isValid, "Proof should be valid")
			} else {
				// For cases where the proof should fail, ensure we get an error
				assert.Error(t, err, "Proof generation should fail for invalid values")
			}
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
			exp: `a86aafc816451783ed59106e681f937c23f20f8175c795600063a887dab1aca2
    ├── a95e7824ca69532428f3050ea7ac90b6ceb8af5b2bc51660f7bf13d64c74e76b
    │   ├── 311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02
    │       (Leaf Value: yolo)
    │   └── 4541f9abff1560090c8554f6336c039c7eba3da710aa83b07452ad1161c9abcd
    │       (Leaf Value: diftp)
    └── 39cd2875a5deae9cd1ec33a13339a3a63f66c8138dd9cb514c0d301438d801a4
        ├── 69d65b9a363d4ca7b25cdaff49ad682c2f42fa51cc765f56b2c6a2a89d038a21
            (Leaf Value: ngmi)
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hashFunc := sha256.New()
			tree, err := NewMerkleTree(tc.values, hashFunc)
			assert.NoError(t, err)

			treeStr := tree.Root.StringifyTree("", false)
			assert.Equal(t, tc.exp, treeStr)
		})
	}
}
