package quic

type sendQueue struct {
	queue       chan *packetBuffer
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	conn        multiSendConn
	multi       bool
}

func newSendQueue(conn multiSendConn) *sendQueue {
	s := &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		queue:       make(chan *packetBuffer, 1),
		multi:       false,
	}
	return s
}

func (h *sendQueue) Send(p *packetBuffer) {
	select {
	case h.queue <- p:
	case <-h.runStopped:
	}
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case p := <-h.queue:

			if p.Multi && h.multi {
				if err := h.conn.WriteMulti(p.Data); err != nil {
					return err
				}
			} else {
				if err := h.conn.Write(p.Data); err != nil {
					return err
				}
			}

			p.Release()
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
