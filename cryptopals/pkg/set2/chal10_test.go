package set2_test

import (
	"bytes"
	"cryptopals/internal/constants"
	"cryptopals/pkg/aes"
	"encoding/base64"
	"os"
	"testing"
)

func TestChal10(t *testing.T) {
	// read file (base64 encoded)
	fileb64, err := os.ReadFile("../../res/set2/10.txt")
	if err != nil {
		t.Error(err)
		return
	}

	// decode
	key := []byte("YELLOW SUBMARINE")
	ct := make([]byte, base64.StdEncoding.DecodedLen(len(fileb64)))
	base64.StdEncoding.Decode(ct, fileb64)
	iv := make([]byte, 16) // 128-bit all zeros

	// decrypt
	pt, _, err := aes.CBCDecrypt(ct, iv, key, 16)
	if err != nil {
		t.Error(err)
		return
	}

	expectedPrefix := "I'm back and I'm ringin' the bell"
	if string(pt)[:len(expectedPrefix)] != expectedPrefix {
		t.Error(constants.ErrWrongResult)
		return
	}
	t.Log("PT:", string(pt))

	// custom test
	{
		myPt := []byte("today is a good day")
		myCt, _, err := aes.CBCEncrypt(myPt, iv, key, 16)
		if err != nil {
			t.Error(err)
			return
		}
		myPt2, _, err := aes.CBCDecrypt(myCt, iv, key, 16)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("PT1:", string(myPt), "\tPT2:", string(myPt2), "\n")
		if !bytes.Equal(myPt, myPt2) {
			t.Error(constants.ErrWrongResult)
		}
	}
}
