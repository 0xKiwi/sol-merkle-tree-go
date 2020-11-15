# Sol-merkle-tree-go

This is a simple merkle tree implementation in go for use within solidity. This was specifically written for use with Uniswaps [merkle-distributor](https://github.com/Uniswap/merkle-distributor).

### Usage
```golang
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

	tree, err := solMerkle.GenerateTreeFromItems(nodes)
	if err != nil {
		return nil, fmt.Errorf("could not generate trie: %v", err)
	}
	distributionRoot := tree.Root()

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
```
