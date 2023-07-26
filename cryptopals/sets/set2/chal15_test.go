package set2_test

import (
	"cryptopals/internal/constants"
	"cryptopals/pkg/pkcs7"
	"testing"
)

func TestChal15(t *testing.T) {
	t.Skip("todo")
	// valid padding, expect no errors
	{
		_, err := pkcs7.Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"))
		if err != nil {
			t.Error(err)
			return
		}
	}
	// invalid padding, expect error
	{
		_, err := pkcs7.Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05"))
		if err == nil {
			t.Error(constants.ErrExpectedError)
			return
		}
	}
	// invalid padding, expect error
	{
		_, err := pkcs7.Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04"))
		if err == nil {
			t.Error(constants.ErrExpectedError)
			return
		}
	}
}
