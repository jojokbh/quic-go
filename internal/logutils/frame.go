package logutils

import (
	"github.com/jojokbh/quic-go/internal/protocol"
	"github.com/jojokbh/quic-go/internal/wire"
	"github.com/jojokbh/quic-go/logging"
)

// ConvertFrame converts a wire.Frame into a logging.Frame.
// This makes it possible for external packages to access the frames.
// Furthermore, it removes the data slices from CRYPTO and STREAM frames.
func ConvertFrame(frame wire.Frame) logging.Frame {
	switch f := frame.(type) {
	case *wire.CryptoFrame:
		return &logging.CryptoFrame{
			Offset: f.Offset,
			Length: protocol.ByteCount(len(f.Data)),
		}
	case *wire.StreamFrame:
		return &logging.StreamFrame{
			StreamID: f.StreamID,
			Offset:   f.Offset,
			Length:   f.DataLen(),
			Fin:      f.Fin,
		}
	default:
		return logging.Frame(frame)
	}
}
