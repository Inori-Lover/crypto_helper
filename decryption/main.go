package decryption

// Default is AES_CTR_256
func Default(ciphertext []byte, key [32]byte) []byte {
	return AesCtr256(ciphertext, key)
}
