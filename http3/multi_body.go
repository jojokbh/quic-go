package http3

import "github.com/jojokbh/quic-go"

func NewMulticastBody(str quic.Stream, done chan<- struct{}, onFrameError func()) *body {
	return newResponseBody(str, done, onFrameError)
}
