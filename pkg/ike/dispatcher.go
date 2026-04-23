package ike

import (
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/pkg/context"
	"github.com/free5gc/tngf/pkg/ike/handler"
	ike_message "github.com/free5gc/tngf/pkg/ike/message"
)

var ikeLog *logrus.Entry

func init() {
	ikeLog = logger.IKELog
}

func isResponseMessage(ikeMessage *ike_message.IKEMessage) bool {
	return (ikeMessage.Flags & ike_message.ResponseBitCheck) != 0
}

func validateAndTrackMessageID(ikeMessage *ike_message.IKEMessage) bool {
	if ikeMessage == nil || ikeMessage.ExchangeType == ike_message.IKE_SA_INIT {
		return true
	}

	if isResponseMessage(ikeMessage) {
		if ikeMessage.ExchangeType != ike_message.CREATE_CHILD_SA {
			return true
		}

		ikeSecurityAssociation, ok := context.TNGFSelf().IKESALoad(ikeMessage.ResponderSPI)
		if !ok {
			// Let handlers process unknown SPI and emit their existing INVALID_IKE_SPI behavior.
			return true
		}

		if ikeSecurityAssociation.ThisUE == nil {
			ikeLog.Warn("Unexpected CREATE_CHILD_SA response: UE context is nil")
			return false
		}

		if _, exists := ikeSecurityAssociation.ThisUE.TemporaryExchangeMsgIDChildSAMapping[ikeMessage.MessageID]; !exists {
			ikeLog.Warnf(
				"Unexpected CREATE_CHILD_SA response MessageID: got %d with no pending exchange",
				ikeMessage.MessageID,
			)
			return false
		}

		return true
	}

	ikeSecurityAssociation, ok := context.TNGFSelf().IKESALoad(ikeMessage.ResponderSPI)
	if !ok {
		// Let handlers process unknown SPI and emit their existing INVALID_IKE_SPI behavior.
		return true
	}

	expectedMessageID := ikeSecurityAssociation.PeerRequestMessageID + 1
	if ikeMessage.MessageID != expectedMessageID {
		ikeLog.Warnf("Unexpected request MessageID: got %d, expected %d", ikeMessage.MessageID, expectedMessageID)
		return false
	}
	ikeSecurityAssociation.PeerRequestMessageID = ikeMessage.MessageID
	return true
}

func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr, msg []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if localAddr.Port == 4500 {
		if len(msg) < 4 {
			ikeLog.Warnf("Drop short UDP/4500 packet: len=%d", len(msg))
			return
		}

		for i := 0; i < 4; i++ {
			if msg[i] != 0 {
				ikeLog.Warn(
					"Received an IKE packet that does not prepend 4 bytes zero from UDP port 4500," +
						" this packet may be the UDP encapsulated ESP. The packet will not be handled.")
				return
			}
		}
		msg = msg[4:]
	}

	ikeMessage := new(ike_message.IKEMessage)

	err := ikeMessage.Decode(msg)
	if err != nil {
		ikeLog.Error(err)
		return
	}

	if !validateAndTrackMessageID(ikeMessage) {
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.INFORMATIONAL:
		handler.HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage)
	default:
		ikeLog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}
