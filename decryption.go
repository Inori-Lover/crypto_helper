package main

type decryption struct{}

// main export
var Decryption decryption

func (c *decryption) Default(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return c.AES_CTR_128(plaintext, key)
}

func (c *decryption) AES_CBC_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *decryption) AES_CBC_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *decryption) AES_CTR_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *decryption) AES_CTR_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *decryption) AES_GCM_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *decryption) AES_GCM_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}
