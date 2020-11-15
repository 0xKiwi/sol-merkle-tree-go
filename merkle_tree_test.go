package solmerkle

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestGenerateTrieFromItems(t *testing.T) {
	tests := []struct {
		name     string
		items    [][]byte
		wantRoot []byte
		wantErr  bool
	}{
		{
			name: "simple sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{4}, 32),
			},
			wantRoot: common.Hex2Bytes("b7427f9168772043b1b25f80c3c6ba6f786ee3b3c3cc6f7721d40e1f57e263e1"),
		},
		{
			name: "larger not sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
			},
			wantRoot: common.Hex2Bytes("1286aba3bcf9de47484160acc9302c836c642443fe27fa871b41ee47b0ceaed0"),
		},
		{
			name: "larger and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
			},
			wantRoot: common.Hex2Bytes("f3300366f2b43137eacdfedfe2bc110fdb488d6f01289309c087ace971691747"),
		},
		{
			name: "very large and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{10}, 32),
				padTo([]byte{20}, 32),
				padTo([]byte{100}, 32),
				padTo([]byte{112}, 32),
				padTo([]byte{80}, 32),
				padTo([]byte{32}, 32),
				padTo([]byte{55}, 32),
				padTo([]byte{56}, 32),
				padTo([]byte{120}, 32),
				padTo([]byte{59}, 32),
				padTo([]byte{70}, 32),
				padTo([]byte{60}, 32),
			},
			wantRoot: common.Hex2Bytes("2e2e5a66fe23ffc25107cfccb3b46ab38a5d0952c6d34d4fa114659259bf9342"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateTreeFromItems(tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTreeFromItems() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := 0; i < len(got.branches); i++ {
				for j := 0; j < len(got.branches[i]); j++ {
					t.Logf("%#x", got.branches[i][j])
				}
			}
			root := got.Root()
			if !bytes.Equal(root, tt.wantRoot) {
				t.Errorf("root() got = %#x, want %#x", root, tt.wantRoot)
			}
		})
	}
}

func TestMerkleProof(t *testing.T) {
	tests := []struct {
		name        string
		items       [][]byte
		itemToProve []byte
		wantProof   [][]byte
		wantErr     bool
	}{
		{
			name: "larger not sorted",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
			},
			itemToProve: common.Hex2Bytes("0c00000000000000000000000000000000000000000000000000000000000000"),
			wantProof: [][]byte{
				common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("bb8672753809914c7d415f12b6dec37fa42357bd158e5a5a0106209f8fdeec75"),
				common.Hex2Bytes("b7427f9168772043b1b25f80c3c6ba6f786ee3b3c3cc6f7721d40e1f57e263e1"),
			},
		},
		{
			name: "larger and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
			},
			itemToProve: common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
			wantProof: [][]byte{
				common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("1a1a55287a82e584e7138c0acd6666344f17ad0c52b3618a34a57ac52a0373ac"),
				common.Hex2Bytes("ccd639cabcb0ffcefeacfacbeb11c70615783a025bfe944b97b77fb2b16ebf3d"),
				common.Hex2Bytes("c6e56afe1fd6fb6a0de84acaafa6a051552413e6eaef27d539414dc679dc9e36"),
			},
		},
		{
			name: "very large and uneven",
			items: [][]byte{
				padTo([]byte{1}, 32),
				padTo([]byte{4}, 32),
				padTo([]byte{3}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{2}, 32),
				padTo([]byte{9}, 32),
				padTo([]byte{16}, 32),
				padTo([]byte{8}, 32),
				padTo([]byte{11}, 32),
				padTo([]byte{12}, 32),
				padTo([]byte{10}, 32),
				padTo([]byte{20}, 32),
				padTo([]byte{100}, 32),
				padTo([]byte{112}, 32),
				padTo([]byte{80}, 32),
				padTo([]byte{32}, 32),
				padTo([]byte{55}, 32),
				padTo([]byte{56}, 32),
				padTo([]byte{120}, 32),
				padTo([]byte{59}, 32),
				padTo([]byte{70}, 32),
				padTo([]byte{60}, 32),
			},
			itemToProve: common.Hex2Bytes("2000000000000000000000000000000000000000000000000000000000000000"),
			wantProof: [][]byte{
				common.Hex2Bytes("1400000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("035929d7fc4417a9f309425389eaed8b13b3e45e364ecea9863d9b4dd69b1a79"),
				common.Hex2Bytes("9c76fa755893aafed6983821b97ba09e7b2180c2eaefcb39b03a71ee08a51d00"),
				common.Hex2Bytes("293b57ac9721cd60fbb5606a4820161ff613b935bfd39153daf3342fc996a3ed"),
				common.Hex2Bytes("ad4641b0d346289fc71b0486c85079e5bd2452a189aff08a06761c24cd68ea7b"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateTreeFromItems(tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTreeFromItems() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			proof, err := got.MerkleProof(tt.itemToProve)
			if (err != nil) != tt.wantErr {
				t.Errorf("MerkleProof() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, pp := range proof {
				if !bytes.Equal(tt.wantProof[i], pp) {
					t.Errorf("proof() got = %#x, want %#x", tt.wantProof[i], pp)
				}
			}
		})
	}
}

func TestVerifyMerkleBranch(t *testing.T) {
	tests := []struct {
		name    string
		root    []byte
		item    []byte
		proof   [][]byte
		success bool
	}{
		{
			name: "simple",
			root: common.Hex2Bytes("b7427f9168772043b1b25f80c3c6ba6f786ee3b3c3cc6f7721d40e1f57e263e1"),
			item: common.Hex2Bytes("0200000000000000000000000000000000000000000000000000000000000000"),
			proof: [][]byte{
				common.Hex2Bytes("0100000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("a72ed8e5e3171a48b8d1faef1360d4456831f9438307e777fa6110e1d6599ecd"),
			},
			success: true,
		},
		{
			name: "larger",
			root: common.Hex2Bytes("1286aba3bcf9de47484160acc9302c836c642443fe27fa871b41ee47b0ceaed0"),
			item: common.Hex2Bytes("0c00000000000000000000000000000000000000000000000000000000000000"),
			proof: [][]byte{
				common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("bb8672753809914c7d415f12b6dec37fa42357bd158e5a5a0106209f8fdeec75"),
				common.Hex2Bytes("b7427f9168772043b1b25f80c3c6ba6f786ee3b3c3cc6f7721d40e1f57e263e1"),
			},
			success: true,
		},
		{
			name: "larger and uneven",
			root: common.Hex2Bytes("f3300366f2b43137eacdfedfe2bc110fdb488d6f01289309c087ace971691747"),
			item: common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
			proof: [][]byte{
				common.Hex2Bytes("1000000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("1a1a55287a82e584e7138c0acd6666344f17ad0c52b3618a34a57ac52a0373ac"),
				common.Hex2Bytes("ccd639cabcb0ffcefeacfacbeb11c70615783a025bfe944b97b77fb2b16ebf3d"),
				common.Hex2Bytes("c6e56afe1fd6fb6a0de84acaafa6a051552413e6eaef27d539414dc679dc9e36"),
			},
			success: true,
		},
		{
			name: "very large and uneven",
			root: common.Hex2Bytes("2e2e5a66fe23ffc25107cfccb3b46ab38a5d0952c6d34d4fa114659259bf9342"),
			item: common.Hex2Bytes("2000000000000000000000000000000000000000000000000000000000000000"),
			proof: [][]byte{
				common.Hex2Bytes("1400000000000000000000000000000000000000000000000000000000000000"),
				common.Hex2Bytes("035929d7fc4417a9f309425389eaed8b13b3e45e364ecea9863d9b4dd69b1a79"),
				common.Hex2Bytes("9c76fa755893aafed6983821b97ba09e7b2180c2eaefcb39b03a71ee08a51d00"),
				common.Hex2Bytes("293b57ac9721cd60fbb5606a4820161ff613b935bfd39153daf3342fc996a3ed"),
				common.Hex2Bytes("ad4641b0d346289fc71b0486c85079e5bd2452a189aff08a06761c24cd68ea7b"),
			},
			success: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyMerkleBranch(tt.root, tt.item, tt.proof)
			if got != tt.success {
				t.Error("GenerateTreeFromItems() failed")
				return
			}
		})
	}
}
