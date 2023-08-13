package set1_test

import (
	"cryptopals/pkg/xor"
	"encoding/hex"
	"testing"
)

func TestChal5_RepeatingKeyXOR(t *testing.T) {
	key := []byte("ICE")
	pt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

	ct := xor.RepeatingKeyXOREncrypt(pt, key)
	ctHex := hex.EncodeToString(ct)

	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if ctHex != expected {
		t.Fatalf("Wrong output.\nHave: %s\nNeed: %s\n", ctHex, expected)
	}
}
