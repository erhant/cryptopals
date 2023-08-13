package set1_test

import (
	"cryptopals/pkg/xor"
	"encoding/hex"
	"testing"
)

func TestChal3_SingleByteXOR(t *testing.T) {
	ct, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatal(err)
	}

	// crack
	res, _, _, err := xor.SingleByteXORDecipher(ct)
	if err != nil {
		t.Fatal(err)
	}

	// there are two answers if you include capital letters too!
	// key 88  --> "Cooking MC's like a pound of bacon" (score: 0.72218305)
	// key 120 --> "cOOKINGmcSLIKEAPOUNDOFBACON"			  (score: 0.72218287)
	expectedRes := "Cooking MC's like a pound of bacon"
	if string(res) != expectedRes {
		t.Fatalf("Wrong output.\nHave: %s\nNeed: %s\n", string(res), expectedRes)
	}
}
