package main

type hash struct{}

// main export
var Hash hash

func (c *hash) Default(plaintext []byte) (hash []byte) {
	return c.Salve_128(plaintext)
}

func (c *hash) Salve_128(plaintext []byte) (hash []byte) {
	return hash
}
