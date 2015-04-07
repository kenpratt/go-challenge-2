package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"io/ioutil"
	"net"
	"testing"
)

func TestReadWriterPing(t *testing.T) {
	priv, pub := &[32]byte{'p', 'r', 'i', 'v'}, &[32]byte{'p', 'u', 'b'}

	r, w := io.Pipe()
	secureR := NewSecureReader(r, priv, pub)
	secureW := NewSecureWriter(w, priv, pub)

	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Decrypt message
	buf := make([]byte, 1024)
	n, err := secureR.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]

	// Make sure we have hello world back
	if res := string(buf); res != "hello world\n" {
		t.Fatalf("Unexpected result: %s != %s", res, "hello world")
	}
}

func TestSecureWriter(t *testing.T) {
	priv, pub := &[32]byte{'p', 'r', 'i', 'v'}, &[32]byte{'p', 'u', 'b'}

	r, w := io.Pipe()
	secureW := NewSecureWriter(w, priv, pub)

	// Make sure we are secure
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if res := string(buf); res == "hello world\n" {
		t.Fatal("Unexpected result. The message is not encrypted.")
	}

	r, w = io.Pipe()
	secureW = NewSecureWriter(w, priv, pub)

	// Make sure we are unique
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf2, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if string(buf) == string(buf2) {
		t.Fatal("Unexpected result. The encrypted message is not unique.")
	}

}

func TestSecureEchoServer(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := "hello world\n"
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(buf[:n]); got != expected {
		t.Fatalf("Unexpected result:\nGot:\t\t%s\nExpected:\t%s\n", got, expected)
	}
}

func TestSecureServe(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	unexpected := "hello world\n"
	if _, err := fmt.Fprintf(conn, unexpected); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got == unexpected {
		t.Fatalf("Unexpected result:\nGot raw data instead of serialized key")
	}
}

func TestSecureDial(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				key := [32]byte{}
				c.Write(key[:])
				buf := make([]byte, 2048)
				n, err := c.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if got := string(buf[:n]); got == "hello world\n" {
					t.Fatal("Unexpected result. Got raw data instead of encrypted")
				}
			}(conn)
		}
	}(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := "hello world\n"
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		t.Fatal(err)
	}
}

//
// Extra tests
//

func TestReadWriterMultiPing(t *testing.T) {
	priv, pub := &[32]byte{'p', 'r', 'i', 'v'}, &[32]byte{'p', 'u', 'b'}

	r, w := io.Pipe()
	secureR := NewSecureReader(r, priv, pub)
	secureW := NewSecureWriter(w, priv, pub)

	// Encrypt hello world
	go func() {
		for i := 0; i < 10; i++ {
			fmt.Fprintf(secureW, "hello world %d\n", i)
		}
		w.Close()
	}()

	buf, err := ioutil.ReadAll(secureR)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure we have hello world back
	expected := "hello world 0\nhello world 1\nhello world 2\nhello world 3\nhello world 4\nhello world 5\nhello world 6\nhello world 7\nhello world 8\nhello world 9\n"
	if res := string(buf); res != expected {
		t.Fatalf("Unexpected result: %s != %s", res, expected)
	}
}

func TestAsymmetricalDecryptionWithBox(t *testing.T) {
	cpub, cpriv, _ := box.GenerateKey(rand.Reader)
	spub, spriv, _ := box.GenerateKey(rand.Reader)

	nonce := &[24]byte{'a'}
	message := []byte{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\n'}

	encrypted := box.Seal([]byte{}, message, nonce, spub, cpriv)
	buf, _ := box.Open([]byte{}, encrypted, nonce, cpub, spriv)

	if res := string(buf); res != "hello world\n" {
		t.Fatalf("Unexpected result: %s != %s", res, "hello world")
	}
}

func TestAsymmetricalDecryption(t *testing.T) {
	cpub, cpriv, _ := box.GenerateKey(rand.Reader)
	spub, spriv, _ := box.GenerateKey(rand.Reader)

	r, w := io.Pipe()
	secureW := NewSecureWriter(w, cpriv, spub)
	secureR := NewSecureReader(r, spriv, cpub)

	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Decrypt message
	buf := make([]byte, 1024)
	n, err := secureR.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]

	if res := string(buf); res != "hello world\n" {
		t.Fatalf("Unexpected result: %s != %s", res, "hello world")
	}
}

func TestAsymmetricalDecryptionEcho(t *testing.T) {
	cpub, cpriv, _ := box.GenerateKey(rand.Reader)
	spub, spriv, _ := box.GenerateKey(rand.Reader)

	upR, upW := io.Pipe()
	downR, downW := io.Pipe()

	secureCW := NewSecureWriter(upW, cpriv, spub)
	secureCR := NewSecureReader(downR, cpriv, spub)

	secureSW := NewSecureWriter(downW, spriv, cpub)
	secureSR := NewSecureReader(upR, spriv, cpub)

	go func() {
		_, err := io.Copy(secureSW, secureSR)
		if err != nil {
			t.Fatal(err)
		}
		downW.Close()
	}()

	go func() {
		fmt.Fprintf(secureCW, "hello world\n")
		fmt.Fprintf(secureCW, "hello world2\n")
		upW.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf, err := ioutil.ReadAll(secureCR)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	expected := "hello world\nhello world2\n"
	if got := string(buf); got != expected {
		t.Fatalf("Unexpected result:\nGot:\t\t%s\nExpected:\t%s\n", got, expected)
	}
}
