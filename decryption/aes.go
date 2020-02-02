package decryption

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto_helper/helper"
)

func aesCBC(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// 如果两个参数是同一变量的话解密会“原地进行”
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext := helper.PKCS7UnPadding(ciphertext)

	return plaintext
}

// AesCbc128 ...
func AesCbc128(ciphertext []byte, key [16]byte) []byte {
	return aesCBC(ciphertext, key[:])
}

// AesCbc192 ...
func AesCbc192(ciphertext []byte, key [24]byte) []byte {
	return aesCBC(ciphertext, key[:])
}

// AesCbc256 ...
func AesCbc256(ciphertext []byte, key [32]byte) []byte {
	return aesCBC(ciphertext, key[:])
}

func aesCTR(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(plaintext, ciphertext)

	return plaintext
}

// AesCtr128 ...
func AesCtr128(ciphertext []byte, key [16]byte) []byte {
	return aesCTR(ciphertext, key[:])
}

// AesCtr192 ...
func AesCtr192(ciphertext []byte, key [24]byte) []byte {
	return aesCTR(ciphertext, key[:])
}

// AesCtr256 ...
func AesCtr256(ciphertext []byte, key [32]byte) []byte {
	return aesCTR(ciphertext, key[:])
}

func aesGCM(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	// AES_GCM 的 最佳iv长度 永远是 12
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv := ciphertext[:12]
	ciphertext = ciphertext[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	return plaintext
}

// AesGcm128 ...
func AesGcm128(ciphertext []byte, key [16]byte) []byte {
	return aesGCM(ciphertext, key[:])
}

// AesGcm192 ...
func AesGcm192(ciphertext []byte, key [24]byte) []byte {
	return aesGCM(ciphertext, key[:])
}

// AesGcm256 ...
func AesGcm256(ciphertext []byte, key [32]byte) []byte {
	return aesGCM(ciphertext, key[:])
}
