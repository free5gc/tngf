package handler

import (
	"net"

	"github.com/free5gc/tngf/pkg/context"
    ike_message "github.com/free5gc/tngf/pkg/ike/message"
)

func SendIKEMessageToUE(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	ikeLog.Trace("Send IKE message to UE")
	ikeLog.Trace("Encoding...")
	pkt, err := message.Encode()
	if err != nil {
		ikeLog.Errorln(err)
		return
	}
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

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

// SendIKEDelete initiates an INFORMATIONAL exchange with a DELETE payload to delete a Child SA.
func SendIKEDelete(ikeSA *context.IKESecurityAssociation, childSA *context.ChildSecurityAssociation) {
    
    responseIKEMessage := new(ike_message.IKEMessage)
    
    var responseIKEPayload ike_message.IKEPayloadContainer

    
    if ikeSA == nil || childSA == nil {
        ikeLog.Error("SendIKEDelete failed: IKESecurityAssociation or ChildSecurityAssociation is nil")
        return
    }
    
    
    ikeSA.InitiatorMessageID++ 
    
    responseIKEMessage.BuildIKEHeader(ikeSA.RemoteSPI, ikeSA.LocalSPI,
        ike_message.INFORMATIONAL, ike_message.InitiatorBitCheck, ikeSA.InitiatorMessageID)
    
    
    ikeLog.Infof("Building IKE DELETE payload for Child SA with SPI [0x%x]", childSA.OutboundSPI)
    
    responseIKEPayload.BuildDelete(ike_message.TypeESP, 4, []uint32{childSA.OutboundSPI})

    
    if err := EncryptProcedure(ikeSA, responseIKEPayload, responseIKEMessage); err != nil {
        ikeLog.Errorf("Encrypting IKE DELETE message failed: %+v", err)
        return
    }

    
    ue := ikeSA.ThisUE
    if ue == nil || ue.IKEConnection == nil {
        ikeLog.Error("Cannot find IKE connection info to send IKE DELETE")
        return
    }
    SendIKEMessageToUE(ue.IKEConnection.Conn, ue.IKEConnection.TNGFAddr, ue.IKEConnection.UEAddr, responseIKEMessage)
    ikeLog.Infof("Sent IKE INFORMATIONAL (DELETE) for Child SA with SPI [0x%x] to UE", childSA.OutboundSPI)
}

func SendIKESADeletion(ikeSA *context.IKESecurityAssociation) {
    responseIKEMessage := new(ike_message.IKEMessage)
    var responseIKEPayload ike_message.IKEPayloadContainer

    if ikeSA == nil {
        ikeLog.Error("SendIKESADeletion failed: IKESecurityAssociation is nil")
        return
    }

    ikeSA.InitiatorMessageID++

    // Build IKE Header for an INFORMATIONAL exchange
    responseIKEMessage.BuildIKEHeader(ikeSA.RemoteSPI, ikeSA.LocalSPI,
        ike_message.INFORMATIONAL, ike_message.InitiatorBitCheck, ikeSA.InitiatorMessageID)

    // Delete IKE SA itself
    ikeLog.Infof("Building IKE DELETE payload for parent IKE SA with SPIs [Local: 0x%x, Remote: 0x%x]",
        ikeSA.LocalSPI, ikeSA.RemoteSPI)
    responseIKEPayload.BuildDelete(ike_message.TypeIKE, 0, nil) // Protocol=IKE, 0 SPIs

    // Encrypt the message
    if err := EncryptProcedure(ikeSA, responseIKEPayload, responseIKEMessage); err != nil {
        ikeLog.Errorf("Encrypting IKE SA DELETE message failed: %+v", err)
        return
    }

    // Send the message to UE
    ue := ikeSA.ThisUE
    if ue == nil || ue.IKEConnection == nil {
        ikeLog.Error("Cannot find IKE connection info to send IKE SA DELETE")
        return
    }
    SendIKEMessageToUE(ue.IKEConnection.Conn, ue.IKEConnection.TNGFAddr, ue.IKEConnection.UEAddr, responseIKEMessage)
    ikeLog.Infof("Sent IKE INFORMATIONAL (DELETE) for IKE SA to UE")
}
