package ngap

import (
	"runtime/debug"

	"github.com/sirupsen/logrus"

	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"
	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/internal/ngap/handler"
	"github.com/free5gc/tngf/pkg/context"
)

var Ngaplog *logrus.Entry

func init() {
	Ngaplog = logger.NgapLog
}

func Dispatch(conn *sctp.SCTPConn, msg []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NgapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// AMF SCTP address
	sctpAddr := conn.RemoteAddr().String()
	// AMF context
	amf, _ := context.TNGFSelf().AMFPoolLoad(sctpAddr)
	// Decode the PDU header before unmarshalling the concrete NGAP message.
	pdu, encodedValue, err := ngapMessage.ParseMessageType(msg)
	if err != nil {
		Ngaplog.Errorf("NGAP decode error: %+v\n", err)
		return
	}
	if err = pdu.UnmarshalBinary(encodedValue); err != nil {
		Ngaplog.Errorf("NGAP decode error: %+v\n", err)
		return
	}

	switch message := pdu.(type) {
	case *ngapMessage.NGReset:
		handler.HandleNGReset(amf, message)
	case *ngapMessage.InitialContextSetupRequest:
		handler.HandleInitialContextSetupRequest(amf, message)
	case *ngapMessage.UEContextModificationRequest:
		handler.HandleUEContextModificationRequest(amf, message)
	case *ngapMessage.UEContextReleaseCommand:
		handler.HandleUEContextReleaseCommand(amf, message)
	case *ngapMessage.DownlinkNASTransport:
		handler.HandleDownlinkNASTransport(amf, message)
	case *ngapMessage.PDUSessionResourceSetupRequest:
		handler.HandlePDUSessionResourceSetupRequest(amf, message)
	case *ngapMessage.PDUSessionResourceModifyRequest:
		handler.HandlePDUSessionResourceModifyRequest(amf, message)
	case *ngapMessage.PDUSessionResourceReleaseCommand:
		handler.HandlePDUSessionResourceReleaseCommand(amf, message)
	case *ngapMessage.ErrorIndication:
		handler.HandleErrorIndication(amf, message)
	case *ngapMessage.UERadioCapabilityCheckRequest:
		handler.HandleUERadioCapabilityCheckRequest(amf, message)
	case *ngapMessage.AMFConfigurationUpdate:
		handler.HandleAMFConfigurationUpdate(amf, message)
	case *ngapMessage.DownlinkRANConfigurationTransfer:
		handler.HandleDownlinkRANConfigurationTransfer(message)
	case *ngapMessage.DownlinkRANStatusTransfer:
		handler.HandleDownlinkRANStatusTransfer(message)
	case *ngapMessage.AMFStatusIndication:
		handler.HandleAMFStatusIndication(message)
	case *ngapMessage.LocationReportingControl:
		handler.HandleLocationReportingControl(message)
	case *ngapMessage.UETNLABindingReleaseRequest:
		handler.HandleUETNLAReleaseRequest(message)
	case *ngapMessage.OverloadStart:
		handler.HandleOverloadStart(amf, message)
	case *ngapMessage.OverloadStop:
		handler.HandleOverloadStop(amf, message)
	case *ngapMessage.NGSetupResponse:
		handler.HandleNGSetupResponse(sctpAddr, conn, message)
	case *ngapMessage.NGResetAcknowledge:
		handler.HandleNGResetAcknowledge(amf, message)
	case *ngapMessage.PDUSessionResourceModifyConfirm:
		handler.HandlePDUSessionResourceModifyConfirm(amf, message)
	case *ngapMessage.RANConfigurationUpdateAcknowledge:
		handler.HandleRANConfigurationUpdateAcknowledge(amf, message)
	case *ngapMessage.NGSetupFailure:
		handler.HandleNGSetupFailure(sctpAddr, conn, message)
	case *ngapMessage.RANConfigurationUpdateFailure:
		handler.HandleRANConfigurationUpdateFailure(amf, message)
	default:
		Ngaplog.Warnf("Not implemented NGAP message: type=%d procedureCode=%d\n",
			pdu.MessageType(), pdu.ProcedureCode())
	}
}
