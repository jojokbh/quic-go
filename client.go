package quic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jojokbh/quic-go/internal/protocol"
	"github.com/jojokbh/quic-go/internal/utils"
	"github.com/jojokbh/quic-go/logging"
	"golang.org/x/net/ipv4"
)

type client struct {
	mutex sync.Mutex

	conn  sendConn
	mconn *net.UDPConn
	// If the client is created with DialAddr, we create a packet conn.
	// If it is started with Dial, we take a packet conn as a parameter.
	createdPacketConn bool

	use0RTT bool

	packetHandlers packetHandlerManager

	tlsConf *tls.Config
	config  *Config

	srcConnID  protocol.ConnectionID
	destConnID protocol.ConnectionID

	initialPacketNumber  protocol.PacketNumber
	hasNegotiatedVersion bool
	version              protocol.VersionNumber

	handshakeChan chan struct{}

	session quicSession

	tracer logging.ConnectionTracer
	logger utils.Logger
}

var (
	// make it possible to mock connection ID generation in the tests
	generateConnectionID           = protocol.GenerateConnectionID
	generateConnectionIDForInitial = protocol.GenerateConnectionIDForInitial
)

// DialAddr establishes a new QUIC connection to a server.
// It uses a new UDP connection and closes this connection when the QUIC session is closed.
// The hostname for SNI is taken from the given address.
// The tls.Config.CipherSuites allows setting of TLS 1.3 cipher suites.
func DialAddr(
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return DialAddrContext(context.Background(), addr, tlsConf, config)
}

// DialAddrEarly establishes a new 0-RTT QUIC connection to a server.
// It uses a new UDP connection and closes this connection when the QUIC session is closed.
// The hostname for SNI is taken from the given address.
// The tls.Config.CipherSuites allows setting of TLS 1.3 cipher suites.
func DialAddrEarly(
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (EarlySession, error) {
	sess, err := dialAddrContext(context.Background(), addr, tlsConf, config, true)
	if err != nil {
		return nil, err
	}
	utils.Logger.WithPrefix(utils.DefaultLogger, "client").Debugf("Returning early session")
	return sess, nil
}

// DialAddrEarly establishes a new 0-RTT QUIC connection to a server.
// It uses a new UDP connection and closes this connection when the QUIC session is closed.
// The hostname for SNI is taken from the given address.
// The tls.Config.CipherSuites allows setting of TLS 1.3 cipher suites.
func DialMultiAddrEarly(
	addr string,
	multiAddr string,
	tlsConf *tls.Config,
	ifat *net.Interface,
	config *Config,
) (EarlySession, error) {
	sess, err := dialMultiAddrContext(context.Background(), addr, multiAddr, tlsConf, ifat, config, true)
	if err != nil {
		return nil, err
	}
	println("Dial mltiaddrEarly")
	utils.Logger.WithPrefix(utils.DefaultLogger, "client").Debugf("Returning early session")
	return sess, nil
}

// DialAddrContext establishes a new QUIC connection to a server using the provided context.
// See DialAddr for details.
func DialMultiAddrContext(
	ctx context.Context,
	addr string,
	multiAddr string,
	tlsConf *tls.Config,
	ifat *net.Interface,
	config *Config,
) (Session, error) {
	//return dialAddrContext(ctx, addr, ifat, tlsConf, config, false)
	return dialMultiAddrContext(ctx, addr, multiAddr, tlsConf, ifat, config, false)
}

// DialAddrContext establishes a new QUIC connection to a server using the provided context.
// See DialAddr for details.
func DialAddrContext(
	ctx context.Context,
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return dialAddrContext(ctx, addr, tlsConf, config, false)
}

func dialMultiAddrContext(
	ctx context.Context,
	addr string,
	multiAddr string,
	tlsConf *tls.Config,
	ifat *net.Interface,
	config *Config,
	use0RTT bool,
) (quicSession, error) {

	//Unicast
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	fmt.Printf("a %s m: %s \n", addr, multiAddr)

	c, err := net.ListenPacket("udp4", multiAddr)
	if err != nil {
		println("Error #1 " + err.Error())
	}

	defer c.Close()

	mHost, _, err := net.SplitHostPort(multiAddr)
	if err != nil {
		println("Split host error " + err.Error())
	}

	group := net.ParseIP(mHost)

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifat, &net.UDPAddr{IP: group}); err != nil {
		// error handling
		println("Error #2 " + err.Error())
	} else {
		println("Joined IGMP")
	}

	multiUdpAddr, err := net.ResolveUDPAddr("udp", multiAddr)
	if err != nil {
		println("Error #3 " + err.Error())
		return nil, err
	}

	multiConn, err := net.DialUDP("udp", nil, multiUdpAddr)
	if err != nil {
		println("Error #4 " + err.Error())
		return nil, err
	}

	return dialMultiContext(ctx, udpConn, multiConn, udpAddr, multiUdpAddr, addr, tlsConf, config, use0RTT, true)
}

func dialAddrContext(
	ctx context.Context,
	addr string,
	tlsConf *tls.Config,
	config *Config,
	use0RTT bool,
) (quicSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return dialContext(ctx, udpConn, udpAddr, addr, tlsConf, config, use0RTT, true)
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The same PacketConn can be used for multiple calls to Dial and Listen,
// QUIC connection IDs are used for demultiplexing the different connections.
// The host parameter is used for SNI.
// The tls.Config must define an application protocol (using NextProtos).
func Dial(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return dialContext(context.Background(), pconn, remoteAddr, host, tlsConf, config, false, false)
}

// DialEarly establishes a new 0-RTT QUIC connection to a server using a net.PacketConn.
// The same PacketConn can be used for multiple calls to Dial and Listen,
// QUIC connection IDs are used for demultiplexing the different connections.
// The host parameter is used for SNI.
// The tls.Config must define an application protocol (using NextProtos).
func DialEarly(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (EarlySession, error) {
	return dialContext(context.Background(), pconn, remoteAddr, host, tlsConf, config, true, false)
}

// DialContext establishes a new QUIC connection to a server using a net.PacketConn using the provided context.
// See Dial for details.
func DialContext(
	ctx context.Context,
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return dialContext(ctx, pconn, remoteAddr, host, tlsConf, config, false, false)
}

func dialContext(
	ctx context.Context,
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
	use0RTT bool,
	createdPacketConn bool,
) (quicSession, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	config = populateClientConfig(config, createdPacketConn)
	packetHandlers, err := getMultiplexer().AddConn(pconn, config.ConnectionIDLength, config.StatelessResetKey, config.Tracer)
	if err != nil {
		return nil, err
	}
	c, err := newClient(pconn, remoteAddr, config, tlsConf, host, use0RTT, createdPacketConn)
	if err != nil {
		return nil, err
	}
	c.packetHandlers = packetHandlers

	if c.config.Tracer != nil {
		c.tracer = c.config.Tracer.TracerForConnection(protocol.PerspectiveClient, c.destConnID)
	}
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c.session, nil
}

func dialMultiContext(
	ctx context.Context,
	pconn net.PacketConn,
	mconn *net.UDPConn,
	remoteAddr net.Addr,
	multiAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
	use0RTT bool,
	createdPacketConn bool,
) (quicSession, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	config = populateClientConfig(config, createdPacketConn)
	packetHandlers, err := getMultiplexer().AddMultiConn(pconn, mconn, config.ConnectionIDLength, config.StatelessResetKey, config.Tracer)
	if err != nil {
		return nil, err
	}
	c, err := newMultiClient(pconn, mconn, remoteAddr, multiAddr, config, tlsConf, host, use0RTT, createdPacketConn)
	if err != nil {
		return nil, err
	}

	c.packetHandlers = packetHandlers

	addr, err := net.ResolveUDPAddr("udp", multiAddr.String())
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.ListenMulticastUDP("udp", nil, addr)
	l.SetReadBuffer(protocol.MaxPacketSizeIPv4)

	//Receive multicast data

	counter := 0
	lost := 0

	go func() {
		for {
			b := make([]byte, protocol.MaxPacketSizeIPv4)
			n, src, err := l.ReadFromUDP(b)
			if err != nil {
				log.Fatal("ReadFromUDP failed:", err)
			}

			//print received data
			log.Println(n, " mulicast read from ", src, " on ")
			counter++

			//False packet loss
			if false {
				//	if counter%10 == 0 {

				lost++
				print("lost packages: ")
				print(counter)
				print("/")
				print(lost)
				println("")
			} else {
				r := &receivedPacket{}
				buf := getPacketBuffer(true)
				r.remoteAddr = remoteAddr
				r.rcvTime = time.Now()
				//r.data = simpleDecrypt(b[:n])
				r.data = b[:n]
				r.buffer = buf

				c.session.handleMultiPacket(r)
			}
		}
	}()

	if c.config.Tracer != nil {
		c.tracer = c.config.Tracer.TracerForConnection(protocol.PerspectiveClient, c.destConnID)
	}
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c.session, nil
}

func simpleDecrypt(raw []byte) []byte {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext := raw

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func newClient(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	config *Config,
	tlsConf *tls.Config,
	host string,
	use0RTT bool,
	createdPacketConn bool,
) (*client, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	if tlsConf.ServerName == "" {
		sni := host
		if strings.IndexByte(sni, ':') != -1 {
			var err error
			sni, _, err = net.SplitHostPort(sni)
			if err != nil {
				return nil, err
			}
		}

		tlsConf.ServerName = sni
	}

	// check that all versions are actually supported
	if config != nil {
		for _, v := range config.Versions {
			if !protocol.IsValidVersion(v) {
				return nil, fmt.Errorf("%s is not a valid QUIC version", v)
			}
		}
	}

	srcConnID, err := generateConnectionID(config.ConnectionIDLength)
	if err != nil {
		return nil, err
	}
	destConnID, err := generateConnectionIDForInitial()
	if err != nil {
		return nil, err
	}
	c := &client{
		srcConnID:         srcConnID,
		destConnID:        destConnID,
		conn:              newSendConn(pconn, remoteAddr),
		createdPacketConn: createdPacketConn,
		use0RTT:           use0RTT,
		tlsConf:           tlsConf,
		config:            config,
		version:           config.Versions[0],
		handshakeChan:     make(chan struct{}),
		logger:            utils.DefaultLogger.WithPrefix("client"),
	}
	return c, nil
}
func newMultiClient(
	pconn net.PacketConn,
	mconn *net.UDPConn,
	remoteAddr net.Addr,
	multiAddr net.Addr,
	config *Config,
	tlsConf *tls.Config,
	host string,
	use0RTT bool,
	createdPacketConn bool,
) (*client, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	if tlsConf.ServerName == "" {
		sni := host
		if strings.IndexByte(sni, ':') != -1 {
			var err error
			sni, _, err = net.SplitHostPort(sni)
			if err != nil {
				return nil, err
			}
		}

		tlsConf.ServerName = sni
	}

	// check that all versions are actually supported
	if config != nil {
		for _, v := range config.Versions {
			if !protocol.IsValidVersion(v) {
				return nil, fmt.Errorf("%s is not a valid QUIC version", v)
			}
		}
	}

	srcConnID, err := generateConnectionID(config.ConnectionIDLength)
	if err != nil {
		return nil, err
	}
	destConnID, err := generateConnectionIDForInitial()
	if err != nil {
		return nil, err
	}
	c := &client{
		srcConnID:         srcConnID,
		mconn:             mconn,
		destConnID:        destConnID,
		conn:              newSendMultiConn(pconn, mconn, remoteAddr, multiAddr),
		createdPacketConn: createdPacketConn,
		use0RTT:           use0RTT,
		tlsConf:           tlsConf,
		config:            config,
		version:           config.Versions[0],
		handshakeChan:     make(chan struct{}),
		logger:            utils.DefaultLogger.WithPrefix("client"),
	}
	return c, nil
}

func (c *client) dial(ctx context.Context) error {
	c.logger.Infof("Starting new connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", c.tlsConf.ServerName, c.conn.LocalAddr(), c.conn.RemoteAddr(), c.srcConnID, c.destConnID, c.version)
	if c.tracer != nil {
		c.tracer.StartedConnection(c.conn.LocalAddr(), c.conn.RemoteAddr(), c.version, c.srcConnID, c.destConnID)
	}

	c.mutex.Lock()

	c.session = newClientSession(
		c.conn,
		c.mconn,
		c.packetHandlers,
		c.destConnID,
		c.srcConnID,
		c.config,
		c.tlsConf,
		c.initialPacketNumber,
		c.version,
		c.use0RTT,
		c.hasNegotiatedVersion,
		c.tracer,
		c.logger,
		c.version,
	)

	c.mutex.Unlock()
	c.packetHandlers.Add(c.srcConnID, c.session)

	errorChan := make(chan error, 1)
	go func() {
		err := c.session.run() // returns as soon as the session is closed
		if !errors.Is(err, errCloseForRecreating{}) && c.createdPacketConn {
			c.packetHandlers.Destroy()
		}
		errorChan <- err
	}()

	// only set when we're using 0-RTT
	// Otherwise, earlySessionChan will be nil. Receiving from a nil chan blocks forever.
	var earlySessionChan <-chan struct{}
	if c.use0RTT {
		earlySessionChan = c.session.earlySessionReady()
	}

	select {
	case <-ctx.Done():
		c.session.shutdown()
		return ctx.Err()
	case err := <-errorChan:
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			c.initialPacketNumber = recreateErr.nextPacketNumber
			c.version = recreateErr.nextVersion
			c.hasNegotiatedVersion = true
			return c.dial(ctx)
		}
		return err
	case <-earlySessionChan:
		// ready to send 0-RTT data
		return nil
	case <-c.session.HandshakeComplete().Done():
		c.packetHandlers.SetMultiStarted()
		// handshake successfully completed
		return nil
	}
}
