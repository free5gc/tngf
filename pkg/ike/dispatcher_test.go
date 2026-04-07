package ike

import (
	"net"
	"testing"
)

func TestDispatchDropsShortUDP4500PacketWithoutPanic(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 12345}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("Dispatch panicked on short UDP/4500 packet: %v", p)
		}
	}()

	Dispatch(nil, localAddr, remoteAddr, []byte{0x00, 0x00, 0x00})
}
