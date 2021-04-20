package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/jojokbh/quic-go/internal/protocol"
	"github.com/jojokbh/quic-go/internal/qtls"
)

func createAEAD(suite *qtls.CipherSuiteTLS13, trafficSecret []byte) cipher.AEAD {
	key := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic key", suite.KeyLen)
	iv := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic iv", suite.IVLen())
	return suite.AEAD(key, iv)
}

type longHeaderSealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector

	// use a single slice to avoid allocations
	nonceBuf []byte
}

var _ LongHeaderSealer = &longHeaderSealer{}

var multiSealer *longHeaderSealer

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	if multiSealer == nil {
		key := []byte("AES256Key-32Characters1234567890")

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		multiSealer = &longHeaderSealer{
			aead:            aesgcm,
			headerProtector: headerProtector,
			nonceBuf:        make([]byte, aead.NonceSize()),
		}
	}
	return &longHeaderSealer{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
	}
}

func (s *longHeaderSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[len(s.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return s.aead.Seal(dst, s.nonceBuf, src, ad)
}

func (s *longHeaderSealer) MultiSeal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	println("Longhead multiseal")
	mNonce := s.nonceBuf[len(s.nonceBuf)-8:]

	binary.BigEndian.PutUint64(mNonce, uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return multiSealer.aead.Seal(dst, multiSealer.nonceBuf, src, ad)
}

func (s *longHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) MultiEncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (o *longHeaderOpener) MultiDecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) Overhead() int {
	return s.aead.Overhead()
}

func (s *longHeaderSealer) MutliOverhead() int {
	return multiSealer.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector

	// use a single slice to avoid allocations
	nonceBuf []byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

var multiOpener *longHeaderOpener

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	if multiOpener == nil {
		key := []byte("AES256Key-32Characters1234567890")

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		multiOpener = &longHeaderOpener{
			aead:            aesgcm,
			headerProtector: headerProtector,
			nonceBuf:        make([]byte, aead.NonceSize()),
		}

	}
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
	}
}

func (o *longHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := o.aead.Open(dst, o.nonceBuf, src, ad)
	if err != nil {
		dec, err = multiSealer.aead.Open(dst, o.nonceBuf, src, ad)
		if err != nil {
			fmt.Println(dst)
			fmt.Println(o.nonceBuf)
			fmt.Println(src)
			fmt.Println(ad)
			err = ErrDecryptionFailed
		}
	}
	return dec, err
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}

type handshakeSealer struct {
	LongHeaderSealer

	dropInitialKeys func()
	dropped         bool
}

func newHandshakeSealer(
	aead cipher.AEAD,
	headerProtector headerProtector,
	dropInitialKeys func(),
	perspective protocol.Perspective,
) LongHeaderSealer {
	sealer := newLongHeaderSealer(aead, headerProtector)
	// The client drops Initial keys when sending the first Handshake packet.
	if perspective == protocol.PerspectiveServer {
		return sealer
	}
	return &handshakeSealer{
		LongHeaderSealer: sealer,
		dropInitialKeys:  dropInitialKeys,
	}
}

func (s *handshakeSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	data := s.LongHeaderSealer.Seal(dst, src, pn, ad)
	if !s.dropped {
		s.dropInitialKeys()
		s.dropped = true
	}
	return data
}

type handshakeOpener struct {
	LongHeaderOpener

	dropInitialKeys func()
	dropped         bool
}

func newHandshakeOpener(
	aead cipher.AEAD,
	headerProtector headerProtector,
	dropInitialKeys func(),
	perspective protocol.Perspective,
) LongHeaderOpener {
	opener := newLongHeaderOpener(aead, headerProtector)
	// The server drops Initial keys when first successfully processing a Handshake packet.
	if perspective == protocol.PerspectiveClient {
		return opener
	}
	return &handshakeOpener{
		LongHeaderOpener: opener,
		dropInitialKeys:  dropInitialKeys,
	}
}

func (o *handshakeOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	dec, err := o.LongHeaderOpener.Open(dst, src, pn, ad)
	if err == nil && !o.dropped {
		o.dropInitialKeys()
		o.dropped = true
	}
	return dec, err
}
