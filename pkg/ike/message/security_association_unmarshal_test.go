package message

import (
	"encoding/binary"
	"strings"
	"testing"
)

func buildProposalWithSingleTransform(transformLength uint16, transformTail []byte) []byte {
	proposalLength := uint16(8) + transformLength
	raw := make([]byte, proposalLength)

	// Proposal header
	raw[0] = 0 // Last proposal
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], proposalLength)
	raw[4] = 1 // Proposal number
	raw[5] = TypeIKE
	raw[6] = 0 // SPI size
	raw[7] = 1 // One transform

	transform := raw[8:]
	transform[0] = 0 // Last transform
	transform[1] = 0
	binary.BigEndian.PutUint16(transform[2:4], transformLength)
	transform[4] = TypeEncryptionAlgorithm
	transform[5] = 0
	binary.BigEndian.PutUint16(transform[6:8], 12)
	copy(transform[8:], transformTail)

	return raw
}

func TestSecurityAssociationUnmarshalRejectsTransformLengthNine(t *testing.T) {
	sa := &SecurityAssociation{}
	raw := buildProposalWithSingleTransform(9, []byte{0x80})

	err := sa.unmarshal(raw)
	if err == nil {
		t.Fatal("expected malformed transform error for transformLength=9")
	}
	if !strings.Contains(err.Error(), "insufficient attribute header bytes") {
		t.Fatalf("unexpected error for transformLength=9: %v", err)
	}
}

func TestSecurityAssociationUnmarshalRejectsTransformLengthTen(t *testing.T) {
	sa := &SecurityAssociation{}
	raw := buildProposalWithSingleTransform(10, []byte{0x80, 0x0e})

	err := sa.unmarshal(raw)
	if err == nil {
		t.Fatal("expected malformed transform error for transformLength=10")
	}
	if !strings.Contains(err.Error(), "insufficient attribute value bytes") {
		t.Fatalf("unexpected error for transformLength=10: %v", err)
	}
}
