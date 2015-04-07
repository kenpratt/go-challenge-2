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

func (e *ReadError) Error() string {
	return e.What
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
