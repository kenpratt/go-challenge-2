package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type SecureWriter struct {
	w    io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := new(SecureWriter)
	sw.w = w
	sw.priv = priv
	sw.pub = pub
	return sw
}

func (sw *SecureWriter) Write(message []byte) (n int, err error) {
	// Convert message to encrypted byte slice with nonce
	nonce := RandomNonce()
	encrypted := box.Seal(nonce[:], message, nonce, sw.pub, sw.priv)
	payloadSize := len(encrypted)

	// Write payload size to buffer
	writeErr := binary.Write(sw.w, binary.LittleEndian, uint32(payloadSize))
	if writeErr != nil {
		fmt.Println("Error writing payloadSize to buffer", writeErr)
		return 0, writeErr
	}

	// Write encrypted message to buffer
	_, writeErr = sw.w.Write(encrypted)
	if writeErr != nil {
		fmt.Println("Error writing encrypted message to buffer", writeErr)
		return 0, writeErr
	}

	return len(message), nil
}

func RandomNonce() *[24]byte {
	var buf [24]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		return nil
	}
	return &buf
}
