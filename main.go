package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
)

type ReadError struct {
	What string
}

type SecureReader struct {
	r    io.Reader
	priv *[32]byte
	pub  *[32]byte
}

type SecureWriter struct {
	w    io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func (e *ReadError) Error() string {
	return e.What
}

func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := new(SecureReader)
	sr.r = r
	sr.priv = priv
	sr.pub = pub
	return sr
}

func (sr *SecureReader) Read(out []byte) (n int, err error) {
	// read up to len(out) + len(overhead) + len(nonce) bytes from stream
	data := make([]byte, len(out)+box.Overhead+24)
	readNum, readErr := sr.r.Read(data)
	if readErr != nil {
		return 0, readErr
	}

	// unpack the nonce and encrypted message
	nonce := data[0:24]
	encrypted := data[24:readNum]

	// decrypt the encrypted message
	var nonceBuf [24]byte
	copy(nonceBuf[:], nonce)
	decrypted, success := box.Open(make([]byte, 0), encrypted, &nonceBuf, sr.pub, sr.priv)
	if success {
		copy(out, decrypted)
		return len(decrypted), nil
	} else {
		return 0, &ReadError{"Error decrypting message"}
	}
}

func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := new(SecureWriter)
	sw.w = w
	sw.priv = priv
	sw.pub = pub
	return sw
}

func (sw *SecureWriter) Write(message []byte) (n int, err error) {
	nonce := RandomNonce()
	encrypted := box.Seal(nonce[:], message, nonce, sw.pub, sw.priv)
	return sw.w.Write(encrypted)
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

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	fmt.Println(os.Args, *port)

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
