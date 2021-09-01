package multicast

import (
	"fmt"
	"io"
)

// The body of a http.Request or http.Response.
type MultiBody struct {
	str io.Reader

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()

	bytesRemainingInFrame uint64
}

func NewResponseMultiBody(str io.Reader, done chan<- struct{}, onFrameError func()) *MultiBody {
	return &MultiBody{
		str:          str,
		onFrameError: onFrameError,
		reqDone:      done,
	}
}

func (r *MultiBody) Read(b []byte) (int, error) {
	n, err := r.readImpl(b)
	if err != nil {
		r.requestDone()
	}
	return n, err
}

func (r *MultiBody) readImpl(b []byte) (int, error) {

	if r.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(r.str)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				// skip HEADERS frames
				continue
			case *dataFrame:
				r.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				r.onFrameError()
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if r.str != nil {

		if r.bytesRemainingInFrame < uint64(len(b)) {
			n, err = r.str.Read(b[:r.bytesRemainingInFrame])
		} else {
			n, err = r.str.Read(b)
		}
		r.bytesRemainingInFrame -= uint64(n)
	} else {
		return 0, fmt.Errorf("Stream is nil %s", b)
	}

	return n, err
}

func (r *MultiBody) requestDone() {
	if r.reqDoneClosed || r.reqDone == nil {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *MultiBody) Close() error {
	r.requestDone()
	// If the EOF was read, CancelRead() is a no-op.
	//r.str.CloseWithError(protocol.ApplicationErrorCode(99), "multibody error")
	return nil
}
