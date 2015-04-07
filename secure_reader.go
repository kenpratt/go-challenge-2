package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type ReadError struct {
	Message string
}

func (e *ReadError) Error() string {
	return e.Message
}

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

func (sr *SecureReader) Read(out []byte) (int, error) {
	// If there isn't a buffer, that means it's time to receive the next encrypted message
	if sr.buffer == nil {
		err := sr.ReadNextEncryptedMessage()
		if err != nil {
			return 0, err
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
	err := binary.Read(sr.r, binary.LittleEndian, &payloadSize)
	if err != nil {
		if err != io.EOF {
			fmt.Println("Error reading payloadSize from buffer", err)
		}
		return err
	}

	// Read the payload
	data := make([]byte, payloadSize)
	_, err = io.ReadFull(sr.r, data)
	if err != nil {
		fmt.Println("Error reading payload from buffer", err)
		return err
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
