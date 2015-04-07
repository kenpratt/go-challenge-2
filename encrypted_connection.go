package main

import (
	"io"
	"net"
)

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
