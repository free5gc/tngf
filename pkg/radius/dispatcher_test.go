package radius_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/free5gc/tngf/pkg/radius"
	radius_message "github.com/free5gc/tngf/pkg/radius/message"
)

func buildAccessRequest(callingStationID string) []byte {
	payload := []byte{radius_message.TypeCallingStationId, uint8(2 + len(callingStationID))}
	payload = append(payload, []byte(callingStationID)...)

	raw := make([]byte, 20)
	raw[0] = radius_message.AccessRequest
	raw[1] = 1
	binary.BigEndian.PutUint16(raw[2:4], uint16(20+len(payload)))
	raw = append(raw, payload...)

	return raw
}

func TestDispatchRecoversFromHandlerPanic(t *testing.T) {
	requestRaw := buildAccessRequest("aa:bb:cc:dd:ee:ff")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Dispatch should recover panic internally, got panic: %v", r)
		}
	}()

	// nil sockets force a panic in response send path; Dispatch must recover and not terminate process.
	radius.Dispatch((*net.UDPConn)(nil), (*net.UDPAddr)(nil), (*net.UDPAddr)(nil), requestRaw)
}
