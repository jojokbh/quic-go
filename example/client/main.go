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
	"time"

	"github.com/jojokbh/quic-go"
	"github.com/jojokbh/quic-go/http3"
	"github.com/jojokbh/quic-go/internal/utils"
	"github.com/jojokbh/quic-go/logging"
	"github.com/jojokbh/quic-go/qlog"
	"golang.org/x/net/ipv4"
)

/*
Client commands with rely
./rely add udp --application-out 224.42.42.1:1236 --tunnel-in 127.0.0.1:9090
./udp-proxy -c -in 224.42.42.1:1235 -out 127.0.0.1:9090 -v 6

*/
func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	hostString := flag.String("h", "localhost:8081", "host string")
	flagMulti := flag.String("m", "224.42.42.1:1235", "multicast addr")
	//insecure := flag.Bool("insecure", true, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()

	srvAddr := *flagMulti
	//urls := [1]string{"https://" + *hostString + "/demo/text"}
	urls := [1]string{"https://" + *hostString + "/i1.m3u8"}
	//urls := [2]string{"https://" + *hostString + "/index.m3u8", "https://" + *hostString + "/index0.ts"}
	//urls := [3]string{"https://" + *hostString + "/index.m3u8", "https://" + *hostString + "/index0.ts", "https://" + *hostString + "/index1.ts"}
	//urls := [8]string{"http://" + *hostString + "/index.m3u8", "http://" + *hostString + "/index0.ts", "http://" + *hostString + "/index1.ts", "http://" + *hostString + "/index2.ts", "http://" + *hostString + "/index3.ts", "http://" + *hostString + "/index4.ts", "http://" + *hostString + "/index5.ts", "http://" + *hostString + "/index6.ts"}
	//urls := [8]string{"https://" + *hostString + "/index.m3u8", "https://" + *hostString + "/index0.ts", "https://" + *hostString + "/index1.ts", "https://" + *hostString + "/index2.ts", "https://" + *hostString + "/index3.ts", "https://" + *hostString + "/index4.ts", "https://" + *hostString + "/index5.ts", "https://" + *hostString + "/index6.ts"}
	//urls := [23]string{"https://" + *hostString + "/i6.m3u8", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/init.mp4", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55977.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55978.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55979.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55980.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55981.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55982.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55983.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55984.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55985.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55986.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55987.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55988.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55989.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55990.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55991.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55992.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55993.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55994.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55996.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55997.m4s", "https://" + *hostString + "/v1EM+vqLVvLf8rlOzoRGfXQ/55998.m4s"}
	//urls := [2]string{"https://localhost/demo/tile", "https://224.42.42.1:1235/demo/tile"}
	//urls := [4]string{"https://"+*hostString+"/demo/tile", "https://224.42.42.1:1235/demo/tile"}

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

	c, err := net.ListenPacket("udp4", srvAddr)
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
		MultiAddr:       srvAddr,
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

		var wg sync.WaitGroup
		wg.Add(len(urls))
	*/
	var src *PassThru
	var reader io.Reader
	reader = bufio.NewReader(reader)

	src = &PassThru{Reader: reader}
	fmt.Println(src)
	now := time.Now()
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		req, _ := http.NewRequest("GET", addr, nil)
		req.Header.Set("multicast", "false")

		rsp, err := hclient.Do(req)
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
		dir = "video"
		fmt.Println(dir)
		// Create the file
		out, err := os.Create(filepath.Join(dir, s))
		if err != nil {
			panic(err)
		}
		defer out.Close()

		//body := &bytes.Buffer{}
		written, err := io.Copy(out, rsp.Body)
		if err != nil {
			log.Fatal(err)
		}
		if *quiet {
			logger.Infof("Request Body: %d bytes", out.Name)
		} else {
			logger.Infof("Request Body: %d bytes", written)
			logger.Infof("%s", out.Name)
		}
		//time.Sleep(time.Second * 1)
		//	wg.Done()
		//}(addr)
	}
	fmt.Println("total time ", time.Now().Sub(now))

	select {}

	//wg.Wait()

}

// PassThru wraps an existing io.Reader.
//
// It simply forwards the Read() call, while displaying
// the results from individual calls to it.
type PassThru struct {
	Reader io.Reader
	total  int64 // Total # of bytes transferred
	done   bool  // Total # of bytes transferred
	//File     *os.File
	buf      []byte // contents are the bytes buf[off : len(buf)]
	off      int    // read at &buf[off], write at &buf[len(buf)]
	lastRead readOp
}

type readOp int8

// Don't use iota for these, as the values need to correspond with the
// names and comments, which is easier to see when being explicit.
const (
	opRead      readOp = -1 // Any other read operation.
	opInvalid   readOp = 0  // Non-read operation.
	opReadRune1 readOp = 1  // Read rune of size 1.
	opReadRune2 readOp = 2  // Read rune of size 2.
	opReadRune3 readOp = 3  // Read rune of size 3.
	opReadRune4 readOp = 4  // Read rune of size 4.
)

// Read 'overrides' the underlying io.Reader's Read method.
// This is the one that will be called by io.Copy(). We simply
// use it to keep track of byte counts and then forward the call.
func (pt *PassThru) Read(p []byte) (int, error) {
	n, err := pt.Reader.Read(p)
	if err == nil {
		pt.total += int64(n)
		fmt.Println("Read", n, "bytes for a total of", pt.total)
	}
	if int64(n) == pt.total {
		//pt.Reader.CancelRead(0)
		fmt.Println("Done pass")
		pt.done = true
	}
	return n, err
}

func (pt *PassThru) stopPassThru() {
	//pt.Reader.CancelRead(1)
	//pt.File.Close()
	fmt.Println("Stop pass")
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
