package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/free5gc/tngf/pkg/context"
	"github.com/free5gc/tngf/pkg/radius/handler"
	radius_message "github.com/free5gc/tngf/pkg/radius/message"
)

func newUDPConnAndAddr(t *testing.T) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("failed to close udp conn after addr cast failure: %v", closeErr)
		}
		t.Fatalf("failed to cast local addr")
	}
	return conn, addr
}

func readRadiusResponse(t *testing.T, conn *net.UDPConn) *radius_message.RadiusMessage {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read udp response: %v", err)
	}

	msg := new(radius_message.RadiusMessage)
	if decodeErr := msg.Decode(buf[:n]); decodeErr != nil {
		t.Fatalf("failed to decode radius response: %v", decodeErr)
	}
	return msg
}

func TestHandleRadiusAccessRequestRejectsShortEAPResponseInEAP5GNAS(t *testing.T) {
	tngfSelf := context.TNGFSelf()
	callingStationID := "11:22:33:44:55:66"
	tngfSelf.DeleteRadiusSession(callingStationID)

	session := tngfSelf.NewRadiusSession(callingStationID)
	session.State = handler.EAP5GNAS
	defer tngfSelf.DeleteRadiusSession(callingStationID)

	senderConn, senderAddr := newUDPConnAndAddr(t)
	defer func() {
		if err := senderConn.Close(); err != nil {
			t.Errorf("failed to close sender conn: %v", err)
		}
	}()
	receiverConn, receiverAddr := newUDPConnAndAddr(t)
	defer func() {
		if err := receiverConn.Close(); err != nil {
			t.Errorf("failed to close receiver conn: %v", err)
		}
	}()

	shortEAP := []byte{radius_message.EAPCodeResponse, 0x01, 0x00, 0x04}

	req := &radius_message.RadiusMessage{
		Code:  radius_message.AccessRequest,
		PktID: 10,
		Auth:  make([]byte, 16),
		Payloads: radius_message.RadiusPayloadContainer{
			{Type: radius_message.TypeCallingStationId, Val: []byte(callingStationID)},
			{Type: radius_message.TypeEAPMessage, Val: shortEAP},
		},
	}

	handler.HandleRadiusAccessRequest(senderConn, senderAddr, receiverAddr, req)

	resp := readRadiusResponse(t, receiverConn)
	if resp.Code != radius_message.AccessReject {
		t.Fatalf("expected Access-Reject, got code %d", resp.Code)
	}
}
