package set1_test

import (
	"cryptopals/pkg/xor"
	"encoding/hex"
	"testing"
)

func TestChal2_FixedXOR(t *testing.T) {
	a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}

	output, err := xor.XOR(a, b)
	if err != nil {
		t.Fatal(err)
	}

	outputStr := hex.EncodeToString(output)
	expectedStr := "746865206b696420646f6e277420706c6179"
	if outputStr != expectedStr {
		t.Errorf("Wrong output.\nHave: %s\nNeed: %s\n", outputStr, expectedStr)
		return
	}
}
