package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jojokbh/quic-go"
	"github.com/jojokbh/quic-go/http3"
	"github.com/jojokbh/quic-go/internal/utils"
	"github.com/jojokbh/quic-go/logging"
	"github.com/jojokbh/quic-go/qlog"
	"golang.org/x/net/ipv4"
)

const (
	srvAddr         = "224.42.42.1:1235"
	maxDatagramSize = 8192
	hostString      = "localhost"
	//hostString = "ottb-ses.redirectme.net"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", true, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	//insecure := flag.Bool("insecure", true, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	//urls := [1]string{"https://" + hostString + ":8081/index6.ts"}
	urls := [8]string{"https://" + hostString + ":8081/index.m3u8", "https://" + hostString + ":8081/index0.ts", "https://" + hostString + ":8081/index1.ts", "https://" + hostString + ":8081/index2.ts", "https://" + hostString + ":8081/index3.ts", "https://" + hostString + ":8081/index4.ts", "https://" + hostString + ":8081/index5.ts", "https://" + hostString + ":8081/index6.ts"}
	//urls := [2]string{"https://localhost:8081/demo/tile", "https://224.42.42.1:1235/demo/tile"}
	//urls := [4]string{"https://"+hostString+":8081/demo/tile", "https://224.42.42.1:1235/demo/tile"}

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}
	tlsconf := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true,
		KeyLogWriter:       keyLog,
	}

	//group := net.IPv4(224, 24, 24, 1)

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		return
	}
	fmt.Println(ifat)

	c, err := net.ListenPacket("udp4", "224.42.42.1:1235")
	if err != nil {
		// error handling
		println("Error listen unicast " + err.Error())
	}
	defer c.Close()
	/*
		addr, err := net.ResolveUDPAddr("udp", "224.42.42.1:1235")
		if err != nil {
			log.Fatal(err)
		}

		l, err := net.ListenMulticastUDP("udp", nil, addr)
		l.SetReadBuffer(maxDatagramSize)

		go func() {
			for {
				b := make([]byte, maxDatagramSize)
				n, src, err := l.ReadFromUDP(b)
				if err != nil {
					log.Fatal("ReadFromUDP failed:", err)
				}

				//print received data
				log.Println(n, "bytes read from", src)
				log.Println(string(b[:n]))
			}
		}()
	*/
	r, _ := ifat.Addrs()

	var aa net.Addr

	for _, a := range r {
		println(a.Network)
		println(a.String)
		aa = a
	}

	//go udpReader(p, " Multicast ", " 224.42.42.1 ")

	qconf.HandshakeTimeout = time.Second * 30

	/*
	   //version expiriment
	   	var v []protocol.VersionNumber

	   	var vv protocol.VersionNumber

	   	vv = 0x51303430

	   	fv := append(v, vv)

	   	qconf.Versions = fv
	*/

	roundTripper := &http3.RoundTripper{
		Ifat:            ifat,
		MultiAddr:       "224.42.42.1:1235",
		TLSClientConfig: tlsconf,
		QuicConfig:      &qconf,
	}
	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
	}

	println("start ")
	println(c)
	println(aa)
	println(tlsconf)
	/*
		session, err := quic.dialMulti(c, aa, "224.42.42.1:1235", tlsconf, &qconf)

		fmt.Println("Client started multisession")

		fmt.Println(session.ConnectionState)

		sendStream, err := session.OpenStream()
		if err != nil {
			panic(err)
		}

		//go multicast.Listen(srvAddr, msgHandler)

		defer sendStream.Close()

		go func() {
			for {
				sendStream.Write([]byte("Ping from client\n"))

				answer, err := bufio.NewReader(sendStream).ReadString('\n')
				if err != nil {
					panic(err)
				}

				fmt.Print("CLIENT: Server replied: " + answer)

				time.Sleep(time.Second)
			}
		}()
	*/

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		//go func(addr string) {
		rsp, err := hclient.Get(addr)
		if err != nil {
			log.Fatal(err)
		}
		logger.Infof("Got response for %s: %#v", addr, rsp)

		ss := strings.Split(addr, "/")
		s := ss[len(ss)-1]

		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		dir = "/home/jones/Documents/quic-go/example/client/video"
		fmt.Println(dir)
		// Create the file
		out, err := os.Create(filepath.Join(dir, s))
		if err != nil {
			panic(err)
		}
		defer out.Close()

		//body := &bytes.Buffer{}
		_, err = io.Copy(out, rsp.Body)
		if err != nil {
			log.Fatal(err)
		}
		if *quiet {
			logger.Infof("Request Body: %d bytes", out.Name)
		} else {
			logger.Infof("Request Body:")
			logger.Infof("%s", out.Name)
		}
		wg.Done()
		//}(addr)
	}
	wg.Wait()

}

func udpReader(c *ipv4.PacketConn, ifname, ifaddr string) {

	log.Printf("udpReader: reading from '%s' on '%s'", ifaddr, ifname)

	defer c.Close()

	buf := make([]byte, 10000)

	for {
		n, cm, _, err := c.ReadFrom(buf)
		if err != nil {
			log.Printf("udpReader: ReadFrom: error %v", err)
			break
		}

		// make a copy because we will overwrite buf
		b := make([]byte, n)
		copy(b, buf)

		log.Printf("udpReader: recv %d bytes from %s to %s on %s", n, cm.Src, cm.Dst, ifname)
	}

	log.Printf("udpReader: exiting '%s'", ifname)
}

const keyBits = 1024

func getCert() (string, string) {

	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"Multicast QUIC Task Force"},
			Country:       []string{"DK"},
			Province:      []string{""},
			Locality:      []string{"Copenhagen"},
			StreetAddress: []string{"A.C. Mayers"},
			PostalCode:    []string{"2450"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 1, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	servCert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Multicast QUIC Task Force"},
			Country:       []string{"DK"},
			Province:      []string{""},
			Locality:      []string{"Copenhagen"},
			StreetAddress: []string{"A.C. Mayers"},
			PostalCode:    []string{"2450"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 1, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: []string{"localhost"},
	}

	servPrivateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		print("#1")
		println(err)
	}

	// signs the TLS certificate by the CA
	servCertBytes, err := x509.CreateCertificate(rand.Reader, servCert, caCert, &servPrivateKey.PublicKey, servPrivateKey)
	if err != nil {
		print("#2")
		println(err)
	}

	servPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(servPrivateKey),
	})

	servCertificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: servCertBytes,
	})

	return string(servCertificatePEM), string(servPrivateKeyPEM)
}
