// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/cheekybits/genny

package quic

import (
	"context"
	"sync"

	"github.com/jojokbh/quic-go/internal/protocol"
	"github.com/jojokbh/quic-go/internal/wire"
)

type outgoingBidiStreamsMap struct {
	mutex sync.RWMutex

	streams map[protocol.StreamNum]streamI

	openQueue      map[uint64]chan struct{}
	lowestInQueue  uint64
	highestInQueue uint64

	nextStream  protocol.StreamNum // stream ID of the stream returned by OpenStream(Sync)
	maxStream   protocol.StreamNum // the maximum stream ID we're allowed to open
	blockedSent bool               // was a STREAMS_BLOCKED sent for the current maxStream

	newStream            func(protocol.StreamNum) streamI
	queueStreamIDBlocked func(*wire.StreamsBlockedFrame)

	closeErr error
}

func newOutgoingBidiStreamsMap(
	newStream func(protocol.StreamNum) streamI,
	queueControlFrame func(wire.Frame),
) *outgoingBidiStreamsMap {
	return &outgoingBidiStreamsMap{
		streams:              make(map[protocol.StreamNum]streamI),
		openQueue:            make(map[uint64]chan struct{}),
		maxStream:            protocol.InvalidStreamNum,
		nextStream:           1,
		newStream:            newStream,
		queueStreamIDBlocked: func(f *wire.StreamsBlockedFrame) { queueControlFrame(f) },
	}
}

func (m *outgoingBidiStreamsMap) OpenStream() (streamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}

	// if there are OpenStreamSync calls waiting, return an error here
	if len(m.openQueue) > 0 || m.nextStream > m.maxStream {
		m.maybeSendBlockedFrame()
		return nil, streamOpenErr{errTooManyOpenStreams}
	}
	return m.openStream(), nil
}

func (m *outgoingBidiStreamsMap) OpenStreamSync(ctx context.Context) (streamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(m.openQueue) == 0 && m.nextStream <= m.maxStream {
		return m.openStream(), nil
	}

	waitChan := make(chan struct{}, 1)
	queuePos := m.highestInQueue
	m.highestInQueue++
	if len(m.openQueue) == 0 {
		m.lowestInQueue = queuePos
	}
	m.openQueue[queuePos] = waitChan
	m.maybeSendBlockedFrame()

	for {
		m.mutex.Unlock()
		select {
		case <-ctx.Done():
			m.mutex.Lock()
			delete(m.openQueue, queuePos)
			return nil, ctx.Err()
		case <-waitChan:
		}
		m.mutex.Lock()

		if m.closeErr != nil {
			return nil, m.closeErr
		}
		if m.nextStream > m.maxStream {
			// no stream available. Continue waiting
			continue
		}
		str := m.openStream()
		delete(m.openQueue, queuePos)
		m.unblockOpenSync()
		return str, nil
	}
}

func (m *outgoingBidiStreamsMap) openStream() streamI {
	s := m.newStream(m.nextStream)
	m.streams[m.nextStream] = s
	m.nextStream++
	return s
}

func (m *outgoingBidiStreamsMap) maybeSendBlockedFrame() {
	if m.blockedSent {
		return
	}

	var streamNum protocol.StreamNum
	if m.maxStream != protocol.InvalidStreamNum {
		streamNum = m.maxStream
	}
	m.queueStreamIDBlocked(&wire.StreamsBlockedFrame{
		Type:        protocol.StreamTypeBidi,
		StreamLimit: streamNum,
	})
	m.blockedSent = true
}

func (m *outgoingBidiStreamsMap) GetStream(num protocol.StreamNum) (streamI, error) {
	m.mutex.RLock()
	if num >= m.nextStream {
		m.mutex.RUnlock()
		return nil, streamError{
			message: "peer attempted to open stream %d",
			nums:    []protocol.StreamNum{num},
		}
	}
	s := m.streams[num]
	m.mutex.RUnlock()
	return s, nil
}

func (m *outgoingBidiStreamsMap) DeleteStream(num protocol.StreamNum) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.streams[num]; !ok {
		return streamError{
			message: "Tried to delete unknown outgoing stream %d",
			nums:    []protocol.StreamNum{num},
		}
	}
	delete(m.streams, num)
	return nil
}

func (m *outgoingBidiStreamsMap) SetMaxStream(num protocol.StreamNum) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if num <= m.maxStream {
		return
	}
	m.maxStream = num
	m.blockedSent = false
	m.unblockOpenSync()
}

func (m *outgoingBidiStreamsMap) unblockOpenSync() {
	if len(m.openQueue) == 0 {
		return
	}
	for qp := m.lowestInQueue; qp <= m.highestInQueue; qp++ {
		c, ok := m.openQueue[qp]
		if !ok { // entry was deleted because the context was canceled
			continue
		}
		close(c)
		m.openQueue[qp] = nil
		m.lowestInQueue = qp + 1
		return
	}
}

func (m *outgoingBidiStreamsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	for _, str := range m.streams {
		str.closeForShutdown(err)
	}
	for _, c := range m.openQueue {
		if c != nil {
			close(c)
		}
	}
	m.mutex.Unlock()
}
