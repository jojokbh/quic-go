package main

import (
	"bufio"
	"crypto/md5"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/jojokbh/quic-go"
	"github.com/jojokbh/quic-go/http3"
	"github.com/jojokbh/quic-go/internal/utils"
	"github.com/jojokbh/quic-go/logging"
	"github.com/jojokbh/quic-go/multicast"

	//"github.com/jojokbh/quic-go/multicast"
	"github.com/jojokbh/quic-go/qlog"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

func setupHandler(www string) http.Handler {
	mux := http.NewServeMux()

	if len(www) > 0 {
		mux.Handle("/", http.FileServer(http.Dir(www)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("%#v\n", r)
			const maxSize = 1 << 30 // 1 GB
			num, err := strconv.ParseInt(strings.ReplaceAll(r.RequestURI, "/", ""), 10, 64)
			if err != nil || num <= 0 || num > maxSize {
				w.WriteHeader(400)
				return
			}
			w.Write(generatePRData(int(num)))
		})
	}

	// accept file uploads and return the MD5 of the uploaded file
	// maximum accepted file size is 1 GB
	mux.HandleFunc("/demo/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			err := r.ParseMultipartForm(1 << 30) // 1 GB
			if err == nil {
				var file multipart.File
				file, _, err = r.FormFile("uploadfile")
				if err == nil {
					var size int64
					if sizeInterface, ok := file.(Size); ok {
						size = sizeInterface.Size()
						b := make([]byte, size)
						file.Read(b)
						md5 := md5.Sum(b)
						fmt.Fprintf(w, "%x", md5)
						return
					}
					err = errors.New("couldn't get uploaded file size")
				}
			}
			utils.DefaultLogger.Infof("Error receiving upload: %#v", err)
		}
		io.WriteString(w, `<html><body><form action="/demo/upload" method="post" enctype="multipart/form-data">
				<input type="file" name="uploadfile"><br>
				<input type="submit">
			</form></body></html>`)
	})

	return mux
}

var www *string

func main() {
	// defer profile.Start().Stop()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
	www = flag.String("www", "", "www data")
	cert := flag.String("cert", "/home/jones/Documents/go-hls/cert/", "Certfolder")
	mACKaddr := flag.String("ack", "192.168.42.52:1234", "ack address")
	tcp := flag.Bool("tcp", false, "also listen on TCP")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	if len(bs) == 0 {
		bs = binds{"localhost:8000"}
		bind = "localhost:8000"
	} else {
		bind = bs[0]
	}

	handler := setupHandler(*www)
	quicConf := &quic.Config{}
	if *enableQlog {
		quicConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("server_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		return
	}
	fmt.Println(ifat)

	files := make(chan string, 1)

	go test(files)

	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error
			if *tcp {
				//certFile, keyFile := testdata.GetCertificatePaths()
				certFile, keyFile := *cert+"server.crt", *cert+"server.key"
				//err = http3.ListenAndServe(bCap, certFile, keyFile, handler)

				http3 := &http3.Server{
					Server:     &http.Server{Handler: handler, Addr: bCap},
					QuicConfig: quicConf,
				}
				server := multicast.MulticastServer{
					Server:     http3,
					Multicast:  &http.Server{Handler: handler, Addr: "224.42.42.1:1235"},
					QuicConfig: quicConf,
				}

				err = server.ListenAndServeTLSMultiFolder(certFile, keyFile, bCap, *mACKaddr, "224.42.42.1:1235", ifat, handler, files)

			} else {
				certFile, keyFile := *cert+"server.crt", *cert+"server.key"
				server := http3.Server{
					Server:     &http.Server{Handler: handler, Addr: bCap},
					QuicConfig: quicConf,
				}
				err = server.ListenAndServeTLS(certFile, keyFile)
			}
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

var bind string

func test(files chan string) {
	var i int64

	fmt.Println("test started")
	hostString := bind
	urls := [7]string{"https://" + hostString + "/index0.ts", "https://" + hostString + "/index1.ts", "https://" + hostString + "/index2.ts", "https://" + hostString + "/index3.ts", "https://" + hostString + "/index4.ts", "https://" + hostString + "/index5.ts", "https://" + hostString + "/index6.ts"}
	filepath := [7]string{*www + "index0.ts", *www + "index1.ts", *www + "index2.ts", *www + "index3.ts", *www + "index4.ts", *www + "index5.ts", *www + "index6.ts"}
	time.Sleep(time.Second * 2)
	for i = 0; i < 2; i++ {
		time.Sleep(time.Millisecond * 10)
		fmt.Println("testing ", urls[i])
		fmt.Println("testing ", filepath[i])

		if i%3 == 0 {
			//	SetMulti(true)
		} else {
			//	SetMulti(true)
		}
		//files <- urls[i]
		go send(files, urls[i])
		//go send(files, filepath[i])
	}
}

func send(files chan string, msg string) {
	fmt.Println("Sending ", msg)
	files <- msg
}
