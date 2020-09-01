// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/jojokbh/quic-go (interfaces: UnknownPacketHandler)

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockUnknownPacketHandler is a mock of UnknownPacketHandler interface
type MockUnknownPacketHandler struct {
	ctrl     *gomock.Controller
	recorder *MockUnknownPacketHandlerMockRecorder
}

// MockUnknownPacketHandlerMockRecorder is the mock recorder for MockUnknownPacketHandler
type MockUnknownPacketHandlerMockRecorder struct {
	mock *MockUnknownPacketHandler
}

// NewMockUnknownPacketHandler creates a new mock instance
func NewMockUnknownPacketHandler(ctrl *gomock.Controller) *MockUnknownPacketHandler {
	mock := &MockUnknownPacketHandler{ctrl: ctrl}
	mock.recorder = &MockUnknownPacketHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockUnknownPacketHandler) EXPECT() *MockUnknownPacketHandlerMockRecorder {
	return m.recorder
}

// handlePacket mocks base method
func (m *MockUnknownPacketHandler) handlePacket(arg0 *receivedPacket) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "handlePacket", arg0)
}

// handlePacket indicates an expected call of handlePacket
func (mr *MockUnknownPacketHandlerMockRecorder) handlePacket(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handlePacket", reflect.TypeOf((*MockUnknownPacketHandler)(nil).handlePacket), arg0)
}

// setCloseError mocks base method
func (m *MockUnknownPacketHandler) setCloseError(arg0 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "setCloseError", arg0)
}

// setCloseError indicates an expected call of setCloseError
func (mr *MockUnknownPacketHandlerMockRecorder) setCloseError(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "setCloseError", reflect.TypeOf((*MockUnknownPacketHandler)(nil).setCloseError), arg0)
}
