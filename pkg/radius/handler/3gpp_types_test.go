package handler_test

import (
	"testing"

	"github.com/free5gc/tngf/pkg/radius/handler"
	radius_message "github.com/free5gc/tngf/pkg/radius/message"
)

func TestUnmarshalEAP5GDataRejectsShortUEIdentityParameter(t *testing.T) {
	// messageID(1) + spare(1) + AN len(2) + paramType(1) + paramLen(1) + value(2) + NAS len(2) + NAS(1)
	codedData := []byte{
		radius_message.EAP5GType5GNAS, 0x00,
		0x00, 0x04,
		radius_message.ANParametersTypeUEIdentity, 0x02,
		0x01, 0x02,
		0x00, 0x01,
		0x7e,
	}

	messageID, anParameters, nasPDU, err := handler.UnmarshalEAP5GData(codedData)
	_ = messageID
	_ = anParameters
	_ = nasPDU
	if err == nil {
		t.Fatal("expected error for short UE Identity parameter, got nil")
	}
}

func TestUnmarshalEAP5GDataRejectsUEIdentityLengthMismatch(t *testing.T) {
	// UE Identity value declares valLen=4 but only 2 bytes follow.
	codedData := []byte{
		radius_message.EAP5GType5GNAS, 0x00,
		0x00, 0x06,
		radius_message.ANParametersTypeUEIdentity, 0x04,
		0x01, 0x00, 0x04, 0xff,
		0x00, 0x01,
		0x7e,
	}

	messageID, anParameters, nasPDU, err := handler.UnmarshalEAP5GData(codedData)
	_ = messageID
	_ = anParameters
	_ = nasPDU
	if err == nil {
		t.Fatal("expected error for UE Identity length mismatch, got nil")
	}
}
