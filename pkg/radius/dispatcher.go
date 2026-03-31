package radius

import (
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/pkg/radius/handler"
	radius_message "github.com/free5gc/tngf/pkg/radius/message"
)

var radiusLog *logrus.Entry

func init() {
	radiusLog = logger.RadiusLog
}

func sendAccessRejectOnRecoveredPanic(
	udpConn *net.UDPConn,
	remoteAddr *net.UDPAddr,
	requestMessage *radius_message.RadiusMessage,
) {
	if udpConn == nil || remoteAddr == nil || requestMessage == nil {
		radiusLog.Warn("Recovered panic but cannot send Access-Reject due to missing socket context")
		return
	}

	response := new(radius_message.RadiusMessage)
	response.BuildRadiusHeader(radius_message.AccessReject, requestMessage.PktID, requestMessage.Auth)

	encodedResponse, err := response.Encode()
	if err != nil {
		radiusLog.Errorf("Recovered panic but failed to encode Access-Reject: %+v", err)
		return
	}

	if _, err = udpConn.WriteToUDP(encodedResponse, remoteAddr); err != nil {
		radiusLog.Errorf("Recovered panic but failed to send Access-Reject: %+v", err)
	}
}

func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr, msg []byte) {
	radiusMessage := new(radius_message.RadiusMessage)
	decoded := false

	defer func() {
		if p := recover(); p != nil {
			logger.RadiusLog.Errorf("Recovered panic in radius dispatch: %v\n%s", p, string(debug.Stack()))
			if decoded {
				sendAccessRejectOnRecoveredPanic(udpConn, remoteAddr, radiusMessage)
			}
		}
	}()

	err := radiusMessage.Decode(msg)
	if err != nil {
		radiusLog.Error(err)
		return
	}
	decoded = true

	switch radiusMessage.Code {
	case radius_message.AccessRequest:
		handler.HandleRadiusAccessRequest(udpConn, localAddr, remoteAddr, radiusMessage)
	default:
		radiusLog.Warnf("Unimplemented radius message type, exchange type: %d", radiusMessage.Code)
	}
}
