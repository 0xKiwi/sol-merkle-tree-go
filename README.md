# Sol-merkle-tree-go

This is a simple merkle tree implementation in go for use within solidity. This was specifically written for use with Uniswaps [merkle-distributor](https://github.com/Uniswap/merkle-distributor).

## Usage
```golang
import (
	"encoding/binary"
	"fmt"
	"math/big"

	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/0xKiwi/sol-merkle-tree-go"
)

type User struct {
	index uint64
	account common.Address
	amount *big.Int
}

type ClaimInfo struct {
	Index  uint64
	Amount string
	Proof  []string
}

func createDistributionTree(holderArray []*tokenHolder) (map[string]ClaimInfo, error) {
    // Put per-user proof data into an array of structs. 
	elements := make([]*User, len(holderArray))
	for i, holder := range holderArray {
		elements[i] = &User{
			index: uint64(i),
			account: holder.addr,
			amount: holder.balance,
		}
	}

    // Solidity hash the data to use as tree leaves. 
    nodes := make([][]byte, len(elements))
    for i, user := range elements {
        hash := solsha3.SoliditySHA3(
            // Types.
            []string{"uint256", "address", "uint256"},
    
            // Values.
            []interface{}{
                fmt.Sprintf("%d", user.index),
                user.account.String(),
                user.amount.String(),
            },
        )
        nodes[i] = hash
    }
    
    // Create the tree.
    tree, err := solmerkle.GenerateTreeFromItems(nodes)
    if err != nil {
        return nil, fmt.Errorf("could not generate trie: %v", err)
    }
    distributionRoot := tree.Root()
    
    // Map claim data to user address, with the merkle proof for claiming from MerkleDistributor. 
    addrToProof := make(map[string]ClaimInfo, len(holderArray))
    for i, holder := range holderArray {
        proof, err := tree.MerkleProof(nodes[i])
        if err != nil {
            return nil, fmt.Errorf("could not generate proof: %v", err)
        }
        addrToProof[holder.addr.String()] = ClaimInfo{
            Index:  uint64(i),
            Amount: holder.balance.String(),
            Proof:  stringArrayFrom2DBytes(proof),
        }
    }
    return addrToProof
}
```
