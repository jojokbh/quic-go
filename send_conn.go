package quic

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/net/ipv4"
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

var newMultiConn *net.UDPConn
var udpAddr *net.UDPAddr

func newSendConn(c net.PacketConn, remote net.Addr) sendConn {

	return &conn{PacketConn: c, remoteAddr: remote}
}

func newSendMultiConn(c net.PacketConn, mConn *net.UDPConn, remote net.Addr, multi net.Addr) multiSendConn {
	println("New send multi conn")

	c2, err := net.ListenPacket("udp4", "224.42.42.1:1235")
	if err != nil {
		println("Error #1 " + err.Error())
	}

	defer c2.Close()

	mHost, port, err := net.SplitHostPort("224.42.42.1:1235")
	if err != nil {
		println("Split host error " + err.Error())
	}

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {

	}

	group := net.ParseIP(mHost)

	p := ipv4.NewPacketConn(c2)

	mP, _ := strconv.Atoi(port)

	udpAddr := &net.UDPAddr{IP: group, Port: mP}
	fmt.Println(group, mP, udpAddr)

	if err := p.JoinGroup(ifat, udpAddr); err != nil {
		// error handling
		println("Error #2 " + err.Error())
	} else {
		println("Joined IGMP")
	}
	multiUdpAddr, err := net.ResolveUDPAddr("udp", "224.42.42.1:1235")
	if err != nil {
		println("Error #3 " + err.Error())
	}

	fmt.Println(multiUdpAddr)

	newMultiConn, err = net.DialUDP("udp", nil, multiUdpAddr)
	if err != nil {
		println("Error #4 " + err.Error())
	}

	return &multiConn{conn: c, mConn: mConn, remoteAddr: remote, multiAddr: multi}
	//return &conn{PacketConn: c, remoteAddr: remote}
}

func (c *conn) Write(p []byte) error {
	fmt.Println("Write Uni")
	_, err := newMultiConn.Write(p)
	if err != nil {
		fmt.Println("newMulti ", err)
	}
	_, err = c.PacketConn.WriteTo(p, c.remoteAddr)
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
	//fmt.Println("Write Multi")
	_, err := newMultiConn.Write(p)
	if err != nil {
		fmt.Println("newMulti ", err)
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
