package solmerkle

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// MerkleTree implements a general purpose Merkle tree.
type MerkleTree struct {
	branches [][][]byte
	depth    uint64
}

// GenerateTreeFromItems constructs a Merkle tree from a sequence of byte slices.
func GenerateTreeFromItems(items [][]byte) (*MerkleTree, error) {
	if len(items) == 0 {
		return nil, errors.New("no items provided to generate Merkle tree")
	}
	// Pad all items to 32 bytes.
	leaves := items
	for i := range leaves {
		leaves[i] = padTo(leaves[i], 32)
	}
	// Sort by byte contents.
	sort.Slice(leaves, func(i, j int) bool {
		return lessThanBytes(leaves[i], leaves[j])
	})

	// Even out if uneven.
	if len(leaves)%2 == 1 {
		duplicate := safeCopyBytes(leaves[len(leaves)-1])
		leaves = append(leaves, duplicate)
	}
	// Append duplicate nodes until even.
	nextPowOfItems := nextPowerOf2(uint64(len(leaves)))
	for len(leaves) < int(nextPowOfItems) {
		leaves = append(leaves, leaves[len(leaves)-2], leaves[len(leaves)-1])
	}

	depth := uint64(math.Log2(float64(len(leaves)) + 1))
	layers := make([][][]byte, depth+1)
	layers[0] = leaves
	for i := uint64(0); i < depth; i++ {
		var updatedValues [][]byte
		for j := 0; j < len(layers[i]); j += 2 {
			concat := SortAndHash(layers[i][j], layers[i][j+1])
			updatedValues = append(updatedValues, concat[:])
		}
		layers[i+1] = updatedValues
	}

	return &MerkleTree{
		branches: layers,
		depth:    depth,
	}, nil
}

// Items returns the original items passed in when creating the Merkle tree.
func (m *MerkleTree) Items() [][]byte {
	return m.branches[0]
}

// Root returns the top-most, Merkle root of the tree.
func (m *MerkleTree) Root() []byte {
	return m.branches[len(m.branches)-1][0]
}

// MerkleProof computes a Proof for a leaf from a tree's branches.
func (m *MerkleTree) MerkleProof(leaf []byte) ([][]byte, error) {
	nextLeaf := leaf
	proof := make([][]byte, m.depth)
	for i := uint64(0); i < m.depth; i++ {
		leftLeaf, rightLeaf := leafPair(m.branches[i], nextLeaf)
		if bytes.Equal(leftLeaf, nextLeaf) {
			proof[i] = rightLeaf
		} else {
			proof[i] = leftLeaf
		}
		nextLeaf = hash(leftLeaf, rightLeaf)
	}
	return proof, nil
}

func (m *MerkleTree) MerkleProofOfIndex(indexOfLeaf uint64) ([][]byte, error) {
	if int(indexOfLeaf) > len(m.branches[0]) {
		return nil, fmt.Errorf("could not find index %d, greater than length %d", indexOfLeaf, m.branches[0])
	}
	return m.MerkleProof(m.branches[0][indexOfLeaf])
}

// VerifyMerkleBranch verifies a Merkle branch against a root of a tree.
func VerifyMerkleBranch(root, item []byte, proof [][]byte) bool {
	node := safeCopyBytes(item)
	for i := 0; i < len(proof); i++ {
		if lessThanBytes(node, proof[i]) {
			node = hash(node[:], proof[i])
		} else {
			node = hash(proof[i], node[:])
		}
	}

	return bytes.Equal(root, node[:])
}

func leafPair(leaves [][]byte, leaf []byte) ([]byte, []byte) {
	var indexOfLeaf int
	for i, item := range leaves {
		if bytes.Equal(item, leaf) {
			indexOfLeaf = i
			break
		}
	}

	var otherLeaf []byte
	left := indexOfLeaf%2 == 0
	if left {
		otherLeaf = safeCopyBytes(leaves[indexOfLeaf+1])
	} else {
		otherLeaf = safeCopyBytes(leaves[indexOfLeaf-1])
	}

	return Sort2Bytes(leaf, otherLeaf)
}

// SortAndHash sorts the 2 bytes and keccak256 hashes them.
func SortAndHash(i []byte, j []byte) []byte {
	sorted1, sorted2 := Sort2Bytes(i, j)
	return hash(sorted1, sorted2)
}

func hash(data ...[]byte) []byte {
	return crypto.Keccak256(data...)
}
