package quic

import (
	"fmt"
	"net"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write([]byte) error
	WriteMulti([]byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type multiSendConn interface {
	Write([]byte) error
	WriteMulti([]byte) error
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

	mConn *net.UDPConn

	remoteAddr net.Addr

	multiAddr net.Addr
}

var _ sendConn = &conn{}
var _ multiSendConn = &multiConn{}

func newSendConn(c net.PacketConn, remote net.Addr) sendConn {

	return &conn{PacketConn: c, remoteAddr: remote}
}

func newSendMultiConn(c net.PacketConn, mConn *net.UDPConn, remote net.Addr, multi net.Addr) multiSendConn {

	return &multiConn{conn: c, mConn: mConn, remoteAddr: remote, multiAddr: multi}
	//return &conn{PacketConn: c, remoteAddr: remote}
}

func (c *conn) Write(p []byte) error {
	fmt.Println("Write Uni")
	_, err := c.PacketConn.WriteTo(p, c.remoteAddr)
	return err
}

func (c *conn) WriteMulti(p []byte) error {
	//fmt.Println("Write Multi")
	_, err := c.PacketConn.WriteTo(p, c.remoteAddr)
	return err
}

func (c *multiConn) Write(p []byte) error {
	//fmt.Println("Write Uni")
	//time.Sleep(time.Microsecond * 10)
	_, err := c.conn.WriteTo(p, c.remoteAddr)
	if err != nil {
		return err
	}

	return err
}

func (c *multiConn) WriteMulti(p []byte) error {

	//time.Sleep(time.Microsecond * 10)
	_, err := c.mConn.Write(p)
	if err != nil {
		println(" ERROR multi " + err.Error())
		return err
	}

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
	return c.remoteAddr
}
