package set1_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestChal1_HexToBase64(t *testing.T) {
	in, err := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}

	out := base64.StdEncoding.EncodeToString(in)

	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if out != expected {
		t.Fatalf("Wrong output.\nHave: %s\nNeed: %s\n", out, expected)
	}
}
