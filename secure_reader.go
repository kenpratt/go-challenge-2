package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type SecureReader struct {
	r      io.Reader
	priv   *[32]byte
	pub    *[32]byte
	buffer []byte
}

func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := new(SecureReader)
	sr.r = r
	sr.priv = priv
	sr.pub = pub
	sr.buffer = nil
	return sr
}

func (sr *SecureReader) Read(out []byte) (n int, err error) {
	// If there isn't a buffer, that means it's time to receive the next encrypted message
	if sr.buffer == nil {
		readErr := sr.ReadNextEncryptedMessage()
		if readErr != nil {
			return 0, readErr
		}
	}

	// Send as much data as possible
	var toSend []byte
	if len(sr.buffer) > len(out) {
		// still too much data, send what we can and stash the rest
		toSend = sr.buffer[0:len(out)]
		sr.buffer = sr.buffer[len(out):]
	} else {
		toSend = sr.buffer
		sr.buffer = nil
	}
	copy(out, toSend)
	return len(toSend), nil
}

// Blocking read until the whole encrypted message is received
func (sr *SecureReader) ReadNextEncryptedMessage() error {
	// Read the payload size out of the buffer
	var payloadSize uint32
	readErr := binary.Read(sr.r, binary.LittleEndian, &payloadSize)
	if readErr != nil {
		if readErr != io.EOF {
			fmt.Println("Error reading payloadSize from buffer", readErr)
		}
		return readErr
	}

	// Read the payload
	data := make([]byte, payloadSize)
	_, readErr = io.ReadFull(sr.r, data)
	if readErr != nil {
		fmt.Println("Error reading payload from buffer", readErr)
		return readErr
	}

	// Unpack the nonce and encrypted message
	nonce := data[0:24]
	encrypted := data[24:]

	// Decrypt the encrypted message
	var nonceBuf [24]byte
	copy(nonceBuf[:], nonce)
	decrypted, success := box.Open(make([]byte, 0), encrypted, &nonceBuf, sr.pub, sr.priv)
	if success {
		sr.buffer = decrypted
		return nil
	} else {
		fmt.Println("Error decrypting message")
		return &ReadError{"Error decrypting message"}
	}
}
