package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/jojokbh/quic-go"
	"github.com/jojokbh/quic-go/http3"
	"github.com/jojokbh/quic-go/internal/testdata"
	"github.com/jojokbh/quic-go/internal/utils"
	"github.com/jojokbh/quic-go/logging"
	"github.com/jojokbh/quic-go/qlog"
	"golang.org/x/net/ipv4"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	//insecure := flag.Bool("insecure", true, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	urls := [2]string{"https://localhost:6121/demo/tile", "https://224.0.0.1:8080/demo/tile"}
	//urls := [4]string{"https://127.0.0.1:6121/demo/tile", "localhost:6121/demo/tile", "127.0.0.1:6060/demo/tile", "localhost:6060/demo/tile"}

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
	testdata.AddRootCA(pool)

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
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsconf,
		QuicConfig:      &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	group := net.IPv4(224, 0, 0, 250)

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		return
	}
	fmt.Println(ifat)

	c, err := net.ListenPacket("udp4", "0.0.0.0:8080")
	if err != nil {
		// error handling
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifat, &net.UDPAddr{IP: group}); err != nil {
		// error handling
	}

	r, _ := ifat.Addrs()

	var aa net.Addr

	for _, a := range r {
		println(a.Network)
		println(a.String)
		aa = a
	}

	session, err := quic.Dial(c, aa, "224.0.0.1:8080", tlsconf, &qconf)

	print(session)

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Fatal(err)
			}
			logger.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				logger.Infof("Request Body: %d bytes", body.Len())
			} else {
				logger.Infof("Request Body:")
				logger.Infof("%s", body.Bytes())
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
