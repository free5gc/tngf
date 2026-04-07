package message_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/free5gc/tngf/pkg/ike/message"
)

func buildProposalWithSingleTransform(transformLength uint16, transformTail []byte) []byte {
	proposalLength := uint16(8) + transformLength
	raw := make([]byte, proposalLength)

	// Proposal header
	raw[0] = 0 // Last proposal
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], proposalLength)
	raw[4] = 1 // Proposal number
	raw[5] = message.TypeIKE
	raw[6] = 0 // SPI size
	raw[7] = 1 // One transform

	transform := raw[8:]
	transform[0] = 0 // Last transform
	transform[1] = 0
	binary.BigEndian.PutUint16(transform[2:4], transformLength)
	transform[4] = message.TypeEncryptionAlgorithm
	transform[5] = 0
	binary.BigEndian.PutUint16(transform[6:8], 12)
	copy(transform[8:], transformTail)

	return raw
}

func decodeSecurityAssociationPayload(transformLength uint16, transformTail []byte) error {
	saBody := buildProposalWithSingleTransform(transformLength, transformTail)
	rawPayload := make([]byte, 4+len(saBody))

	// IKE payload generic header: NoNext + flags + payload length.
	rawPayload[0] = 0
	rawPayload[1] = 0
	binary.BigEndian.PutUint16(rawPayload[2:4], uint16(len(rawPayload)))
	copy(rawPayload[4:], saBody)

	var container message.IKEPayloadContainer
	return container.Decode(uint8(message.TypeSA), rawPayload)
}

func TestSecurityAssociationUnmarshalRejectsTransformLengthNine(t *testing.T) {
	err := decodeSecurityAssociationPayload(9, []byte{0x80})
	if err == nil {
		t.Fatal("expected malformed transform error for transformLength=9")
	}
	if !strings.Contains(err.Error(), "insufficient attribute header bytes") {
		t.Fatalf("unexpected error for transformLength=9: %v", err)
	}
}

func TestSecurityAssociationUnmarshalRejectsTransformLengthTen(t *testing.T) {
	err := decodeSecurityAssociationPayload(10, []byte{0x80, 0x0e})
	if err == nil {
		t.Fatal("expected malformed transform error for transformLength=10")
	}
	if !strings.Contains(err.Error(), "insufficient attribute value bytes") {
		t.Fatalf("unexpected error for transformLength=10: %v", err)
	}
}
