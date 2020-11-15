package solmerkle

import (
	"testing"
)

func Test_nextPowerOf2(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want uint64
	}{
		{
			name: "0",
			n:    0,
			want: 0,
		},
		{
			name: "4",
			n:    4,
			want: 4,
		},
		{
			name: "3",
			n:    3,
			want: 4,
		},
		{
			name: "8",
			n:    8,
			want: 8,
		},
		{
			name: "9",
			n:    9,
			want: 16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextPowerOf2(tt.n); got != tt.want {
				t.Errorf("nextPowerOf2() = %v, want %v", got, tt.want)
			}
		})
	}
}
