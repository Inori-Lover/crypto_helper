package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/Inori-Lover/crypto_helper/hash"
	"github.com/Inori-Lover/crypto_helper/helper"
)

func aesCBC(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	plaintext = helper.PKCS7Padding(plaintext, blockSize)
	iv := hash.Blake2(plaintext)[:blockSize]

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...)
}

// AesCbc128 ...
func AesCbc128(plaintext []byte, key [16]byte) []byte {
	return aesCBC(plaintext, key[:])
}

// AesCbc192 ...
func AesCbc192(plaintext []byte, key [24]byte) []byte {
	return aesCBC(plaintext, key[:])
}

// AesCbc256 ...
func AesCbc256(plaintext []byte, key [32]byte) []byte {
	return aesCBC(plaintext, key[:])
}

func aesCTR(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := hash.Blake2(plaintext)[:blockSize]

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertext, plaintext)

	return append(iv, ciphertext...)
}

// AesCtr128 ...
func AesCtr128(plaintext []byte, key [16]byte) []byte {
	return aesCTR(plaintext, key[:])
}

// AesCtr192 ...
func AesCtr192(plaintext []byte, key [24]byte) []byte {
	return aesCTR(plaintext, key[:])
}

// AesCtr256 ...
func AesCtr256(plaintext []byte, key [32]byte) []byte {
	return aesCTR(plaintext, key[:])
}

func aesGCM(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	// AES_GCM 的 最佳iv长度 永远是 12 字节
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv := hash.Blake2(plaintext)[:12]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	return append(iv, ciphertext...)
}

// AesGcm128 ...
func AesGcm128(plaintext []byte, key [16]byte) []byte {
	return aesGCM(plaintext, key[:])
}

// AesGcm192 ...
func AesGcm192(plaintext []byte, key [24]byte) []byte {
	return aesGCM(plaintext, key[:])
}

// AesGcm256 ...
func AesGcm256(plaintext []byte, key [32]byte) []byte {
	return aesGCM(plaintext, key[:])
}
