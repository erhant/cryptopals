package set1_test

import (
	"cryptopals/internal/common"
	"cryptopals/pkg/xor"
	"encoding/base64"
	"os"
	"testing"
)

func TestHammingDistance(t *testing.T) {
	s1 := []byte("this is a test")
	s2 := []byte("wokka wokka!!!")
	dist, err := common.HammingDistance(s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	expectedDist := 37
	if dist != expectedDist {
		t.Fatalf("Wrong output.\nHave: %d\nNeed: %d\n", dist, expectedDist)
	}
}

func TestChal6_BreakRepeatingKeyXOR(t *testing.T) {
	// t.Skip("skip: test is a bit long")

	// read file (base64 encoded)
	fileb64, err := os.ReadFile("../../res/set1/6.txt")
	if err != nil {
		t.Fatal(err)
	}

	// decode
	ct, err := base64.StdEncoding.DecodeString(string(fileb64))
	if err != nil {
		t.Fatal(err)
	}

	// decipher
	pt, key, err := xor.RepeatingKeyXORDecipher(ct)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(pt), "\n")

	expectedKey := "Terminator X: Bring the noise"
	// there are two answers if you include capital letters too!
	// key: teRmINaTORx:brINGthENOISE
	// key: Terminator X: Bring the noise
	if string(key) != expectedKey {
		t.Fatalf("Wrong output.\nHave: %s\nNeed: %s\n", key, expectedKey)
	}

}
