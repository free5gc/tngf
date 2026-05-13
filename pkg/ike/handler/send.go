package handler

import (
	"net"
	"sync"
	"time"

	ike_message "github.com/free5gc/tngf/pkg/ike/message"
)

type cachedResponseKey struct {
	responderSPI uint64
	messageID    uint32
}

type cachedResponse struct {
	packet    []byte
	expiresAt time.Time
}

const cachedResponseLifetime = 5 * time.Minute

var cachedResponses sync.Map

func cacheIKEMessageResponse(message *ike_message.IKEMessage, packet []byte) {
	if message == nil || message.ExchangeType == ike_message.IKE_SA_INIT ||
		(message.Flags&ike_message.ResponseBitCheck) == 0 {
		return
	}

	key := cachedResponseKey{
		responderSPI: message.ResponderSPI,
		messageID:    message.MessageID,
	}
	cachedResponses.Store(key, cachedResponse{
		packet:    append([]byte(nil), packet...),
		expiresAt: time.Now().Add(cachedResponseLifetime),
	})
}

func buildIKEPacketForUDP(srcAddr *net.UDPAddr, pkt []byte) []byte {
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr != nil && srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		return append(prependZero, pkt...)
	}
	return pkt
}

func sendIKEPacketToUE(udpConn *net.UDPConn, dstAddr *net.UDPAddr, pkt []byte) {
	ikeLog.Trace("Sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		ikeLog.Error(err)
		return
	}
	if n != len(pkt) {
		ikeLog.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(pkt), n)
		return
	}
}

func cleanupExpiredCachedResponses(now time.Time) {
	cachedResponses.Range(func(key, value interface{}) bool {
		response := value.(cachedResponse)
		if now.After(response.expiresAt) {
			cachedResponses.Delete(key)
		}
		return true
	})
}

func ForgetCachedIKEResponsesBefore(responderSPI uint64, messageID uint32) {
	now := time.Now()
	cachedResponses.Range(func(key, value interface{}) bool {
		responseKey := key.(cachedResponseKey)
		response := value.(cachedResponse)
		if now.After(response.expiresAt) ||
			(responseKey.responderSPI == responderSPI && responseKey.messageID < messageID) {
			cachedResponses.Delete(key)
		}
		return true
	})
}

func RetransmitCachedIKEMessageToUE(
	udpConn *net.UDPConn,
	_ *net.UDPAddr,
	dstAddr *net.UDPAddr,
	responderSPI uint64,
	messageID uint32,
) bool {
	key := cachedResponseKey{
		responderSPI: responderSPI,
		messageID:    messageID,
	}
	cachedResponseValue, ok := cachedResponses.Load(key)
	if !ok {
		return false
	}
	response := cachedResponseValue.(cachedResponse)
	if time.Now().After(response.expiresAt) {
		cachedResponses.Delete(key)
		return false
	}

	sendIKEPacketToUE(udpConn, dstAddr, append([]byte(nil), response.packet...))
	return true
}

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	ikeLog.Trace("Send IKE message to UE")
	ikeLog.Trace("Encoding...")
	pkt, err := message.Encode()
	if err != nil {
		ikeLog.Errorln(err)
		return
	}
	pkt = buildIKEPacketForUDP(srcAddr, pkt)
	cleanupExpiredCachedResponses(time.Now())
	cacheIKEMessageResponse(message, pkt)
	sendIKEPacketToUE(udpConn, dstAddr, pkt)
}
