package quic

import (
	"net"

	"golang.org/x/net/ipv4"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write([]byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type multiSendConn interface {
	Write([]byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type conn struct {
	net.PacketConn

	remoteAddr net.Addr
}

type multiConn struct {
	conn net.PacketConn

	mConn ipv4.PacketConn

	remoteAddr net.Addr
}

var _ sendConn = &conn{}

func newSendConn(c net.PacketConn, remote net.Addr) sendConn {

	return &conn{PacketConn: c, remoteAddr: remote}
}

func newSendMultiConn(c net.PacketConn, mConn ipv4.PacketConn, remote net.Addr) multiSendConn {

	return &multiConn{conn: c, mConn: mConn, remoteAddr: remote}
}

func (c *conn) Write(p []byte) error {
	_, err := c.PacketConn.WriteTo(p, c.remoteAddr)
	return err
}

func (c *multiConn) Write(p []byte) error {
	_, err := c.conn.WriteTo(p, c.remoteAddr)

	_, err = c.mConn.WriteTo(p, nil, c.mConn.LocalAddr())

	return err
}

func (c *multiConn) Close() error {
	err := c.conn.Close()
	if err != nil {
		return err
	}
	err = c.mConn.Close()

	return err
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *multiConn) LocalAddr() net.Addr {
	return c.mConn.LocalAddr()
}

func (c *multiConn) RemoteAddr() net.Addr {
	return c.RemoteAddr()
}
