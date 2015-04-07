package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
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
	buf := bufio.NewReader(sr.r)

	// Read the payload size out of the buffer
	var rawPayloadSize uint64
	bufErr := binary.Read(buf, binary.LittleEndian, &rawPayloadSize)
	if bufErr != nil {
		if bufErr != io.EOF {
			fmt.Println("Error reading payloadSize from buffer", bufErr)
		}
		return 0, bufErr
	}
	var payloadSize int = int(rawPayloadSize)

	// Ensure there's enough data to read
	// TODO Instead of returning error, try sleeping until there's more data?
	if buf.Buffered() < int(payloadSize) {
		fmt.Printf("Not enough data in buffer to read (want: %d, have: %d)\n", payloadSize, buf.Buffered())
		return 0, &ReadError{"Not enough data to read message"}
	}

	// Read the payload
	data := make([]byte, payloadSize)
	nRead, bufErr := buf.Read(data)
	if bufErr != nil {
		fmt.Println("Error reading payload from buffer", bufErr)
		return 0, bufErr
	}
	if nRead < payloadSize {
		fmt.Printf("Not enough bytes read from buffer (wanted: %d, got: %d)\n", payloadSize, nRead)
		return nRead, &ReadError{"Didn't read enough data from buffer"}
	}

	// Unpack the nonce and encrypted message
	nonce := data[0:24]
	encrypted := data[24:]

	// Decrypt the encrypted message
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
	// Convert message to encrypted byte slice with nonce
	nonce := RandomNonce()
	encrypted := box.Seal(nonce[:], message, nonce, sw.pub, sw.priv)
	payloadSize := len(encrypted)

	// Write payload size to buffer
	buf := bufio.NewWriter(sw.w)
	bufErr := binary.Write(buf, binary.LittleEndian, uint64(payloadSize))
	if bufErr != nil {
		fmt.Println("Error writing payloadSize to buffer", bufErr)
		return 0, bufErr
	}

	// Write encrypted message to buffer
	_, bufErr = buf.Write(encrypted)
	if bufErr != nil {
		fmt.Println("Error writing encrypted message to buffer", bufErr)
		return 0, bufErr
	}

	// Flush the buffer
	flushErr := buf.Flush()
	if flushErr != nil {
		fmt.Println("Error flushing buffer", flushErr)
		return 0, flushErr
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

type EncryptedConnection struct {
	conn net.Conn
	sw   io.Writer
	sr   io.Reader
}

func NewEncryptedConnection(conn net.Conn, priv, pub *[32]byte) io.ReadWriteCloser {
	ec := new(EncryptedConnection)
	ec.conn = conn
	ec.sw = NewSecureWriter(conn, priv, pub)
	ec.sr = NewSecureReader(conn, priv, pub)
	return ec
}

func (ec *EncryptedConnection) Read(out []byte) (n int, err error) {
	return ec.sr.Read(out)
}

func (ec *EncryptedConnection) Write(message []byte) (n int, err error) {
	return ec.sw.Write(message)
}

func (ec *EncryptedConnection) Close() error {
	return ec.conn.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	// Generate a key/val pair
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating a key pair", err)
		return nil, err
	}

	// Connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Error connecting to server", err)
		return nil, err
	}

	// Write our pub key
	_, err = conn.Write(pub[:])
	if err != nil {
		fmt.Println("Error sending public key to server", err)
		return nil, err
	}

	// Read the server pub key
	var peerPub [32]byte
	_, err = conn.Read(peerPub[:])
	if err != nil {
		fmt.Println("Error reading public key from server", err)
		return nil, err
	}

	// Create an encrypted connection that well encrypt all traffic over conn
	ec := NewEncryptedConnection(conn, priv, &peerPub)
	return ec, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			// Generate a key/val pair
			pub, priv, err := box.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println("Error generating a key pair", err)
				conn.Close()
				return
			}

			// Read the client pub key
			var peerPub [32]byte
			_, err = conn.Read(peerPub[:])
			if err != nil {
				fmt.Println("Error reading public key from client", err)
				conn.Close()
				return
			}

			// Write our pub key
			_, err = conn.Write(pub[:])
			if err != nil {
				fmt.Println("Error sending public key to client", err)
				conn.Close()
				return
			}

			// Create encrypted streams, and link them to echo results back to client
			sr := NewSecureReader(conn, priv, &peerPub)
			sw := NewSecureWriter(conn, priv, &peerPub)
			io.Copy(sw, sr)
		}(conn)
	}
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

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
