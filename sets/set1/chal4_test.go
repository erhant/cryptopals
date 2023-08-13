package set1_test

import (
	"bufio"
	"cryptopals/pkg/xor"
	"encoding/hex"
	"math"
	"os"
	"testing"
)

func TestChal4_SingleByteXOR_Detect(t *testing.T) {
	t.Skip("skip: test is a bit long")

	file, err := os.Open("../../res/set1/4.txt")
	if err != nil {
		t.Error(err)
		return
	}
	defer file.Close()

	// read line by line
	var score float32 = math.MaxFloat32
	var ans []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ct := scanner.Bytes()

		// decode hex
		ctDec, err := hex.DecodeString(string(ct))
		if err != nil {
			t.Fatal(err)
		}

		// crack line
		pt, _, s, err := xor.SingleByteXORDecipher(ctDec)
		if err != nil {
			t.Fatal(err)
		}

		// update score (cost)
		if s <= score {
			ans = pt
			score = s
			// fmt.Println("Better:", string(ans), "\nKey:", key, "\nScore:", score)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	expected := "Now that the party is jumping\n"
	if string(ans) != expected {
		t.Fatalf("Wrong output.\nHave: %s\nNeed: %s\n", string(ans), expected)
	}
}
