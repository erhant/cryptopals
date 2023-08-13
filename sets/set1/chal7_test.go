package set1_test

import (
	"cryptopals/internal/constants"
	"cryptopals/pkg/aes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestChal7_AES_ECB(t *testing.T) {
	// read file (base64 encoded)
	fileb64, err := os.ReadFile("../../res/set1/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	// decode
	ct, err := base64.StdEncoding.DecodeString(string(fileb64))
	if err != nil {
		t.Fatal(err)
	}

	// decrypt
	key := []byte("YELLOW SUBMARINE")
	ptBytes, err := aes.ECBDecrypt(ct, key, 16)
	if err != nil {
		t.Fatal(err)
	}
	pt := string(ptBytes)

	// trim EOT, new-line, space
	pt = strings.Trim(pt, "\x04\n ")
	fmt.Println(pt)

	// check prefix match
	expectedPrefix := "I'm back and I'm ringin' the bell"
	ptPrefix := pt[:len(expectedPrefix)]
	if ptPrefix != expectedPrefix {
		t.Fatal(constants.ErrWrongResult, ptPrefix)
	}

	// check suffix match
	expectedSuffix := "Play that funky music"
	ptSuffix := pt[len(pt)-len(expectedSuffix):]
	if ptSuffix != expectedSuffix {
		t.Fatal(constants.ErrWrongResult, ptSuffix)
	}
}
