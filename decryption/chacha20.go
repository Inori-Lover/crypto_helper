package decryption

import (
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Inori-Lover/crypto_helper/helper"
)

func xChacha20(ciphertext []byte, key []byte) []byte {
	iv := ciphertext[:chacha20.NonceSizeX]
	ciphertext = ciphertext[chacha20.NonceSizeX:]

	mode, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	plaintext := make([]byte, len(ciphertext))
	mode.XORKeyStream(plaintext, ciphertext)

	return plaintext
}

// XChacha20 ...
func XChacha20(ciphertext []byte, key [chacha20.KeySize]byte) []byte {
	return xChacha20(ciphertext, key[:])
}

func xChacha20poly1305(ciphertext []byte, key []byte) []byte {
	iv := ciphertext[:chacha20poly1305.NonceSizeX]
	ciphertext = ciphertext[chacha20poly1305.NonceSizeX:]

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	plaintext, err := aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	return plaintext
}

// XChacha20poly1305 ...
func XChacha20poly1305(ciphertext []byte, key [chacha20poly1305.KeySize]byte) []byte {
	return xChacha20poly1305(ciphertext, key[:])
}
