package message

import (
	"encoding/hex"
	"testing"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/tngf/pkg/context"
)

func TestBuildMessageGoldenOutput(t *testing.T) {
	setupTestContext()
	ue := testTNGFUe()
	nasPdu := []byte{0x7e, 0x00, 0x41, 0x01, 0x02, 0x03}
	cause := testCause()
	pduSession := testPDUSession()

	setupTransfer, err := BuildPDUSessionResourceSetupResponseTransfer(pduSession)
	if err != nil {
		t.Fatalf("BuildPDUSessionResourceSetupResponseTransfer() error = %v", err)
	}

	responseList := &ngapType.PDUSessionResourceSetupListSURes{
		List: []ngapType.PDUSessionResourceSetupItemSURes{
			{
				PDUSessionID: ngapType.PDUSessionID{Value: 10},
				PDUSessionResourceSetupResponseTransfer: aper.OctetString(
					setupTransfer,
				),
			},
		},
	}

	allowedNSSAI := &ngapType.AllowedNSSAI{
		List: []ngapType.AllowedNSSAIItem{
			{
				SNSSAI: ngapType.SNSSAI{
					SST: ngapType.SST{Value: aper.OctetString{0x01}},
					SD:  &ngapType.SD{Value: aper.OctetString{0x11, 0x22, 0x33}},
				},
			},
		},
	}

	tests := []struct {
		name        string
		expectedHex string
		build       func() ([]byte, error)
	}{
		{
			name:        "BuildNGSetupRequest",
			expectedHex: "0015003b000003001b000ec000f000090002f83900010203040052400e0580667265653547435f544e47460066001000000000010002f83900001008010203",
			build:       BuildNGSetupRequest,
		},
		{
			name:        "BuildInitialContextSetupResponse",
			expectedHex: "200e0010000002000a40032001c800554002007b",
			build: func() ([]byte, error) {
				return BuildInitialContextSetupResponse(ue, nil, nil, nil)
			},
		},
		{
			name:        "BuildInitialUEMessage",
			expectedHex: "000f403500000500550002007b00260007067e004101020300790013c000f4400e00060304050607080f80c0000201005a0001180070400100",
			build: func() ([]byte, error) {
				return BuildInitialUEMessage(ue, nasPdu, nil)
			},
		},
		{
			name:        "BuildInitialUEMessageWithGUTIAndAllowedNSSAI",
			expectedHex: "000f404f00000800550002007b00260007067e004101020300790013c000f4400e00060304050607080f80c0000201005a000118001a00070080c0010203040003400202000070400100000040050201112233",
			build: func() ([]byte, error) {
				ueWithGUTI := *ue
				ueWithGUTI.Guti = "2089301020301020304"
				return BuildInitialUEMessage(&ueWithGUTI, nasPdu, allowedNSSAI)
			},
		},
		{
			name:        "BuildUplinkNASTransport",
			expectedHex: "002e4032000004000a00032001c800550002007b00260007067e004101020300794013c000f4400e00060304050607080f80c0000201",
			build: func() ([]byte, error) {
				return BuildUplinkNASTransport(ue, nasPdu)
			},
		},
		{
			name:        "BuildPDUSessionResourceSetupResponse",
			expectedHex: "201d0027000003000a40032001c800554002007b004b401300000a0f0003e00a0000010102030404010240",
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponse(ue, responseList, nil, nil)
			},
		},
		{
			name:        "BuildPDUSessionResourceSetupResponseTransfer",
			expectedHex: "0003e00a0000010102030404010240",
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupResponseTransfer(pduSession)
			},
		},
		{
			name:        "BuildPDUSessionResourceSetupUnsuccessfulTransfer",
			expectedHex: "00a0",
			build: func() ([]byte, error) {
				return BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.build()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != tt.expectedHex {
				t.Fatalf("%s() = %s, want %s", tt.name, gotHex, tt.expectedHex)
			}
		})
	}
}

func setupTestContext() {
	tngfSelf := context.TNGFSelf()
	tngfSelf.NFInfo = context.TNGFNFInfo{
		GlobalTNGFID: context.GlobalTNGFID{
			PLMNID: context.PLMNID{
				Mcc: "208",
				Mnc: "93",
			},
			TNGFID: 0x01020304,
		},
		RanNodeName: "free5GC_TNGF",
		SupportedTAList: []context.SupportedTAItem{
			{
				TAC: "000001",
				BroadcastPLMNList: []context.BroadcastPLMNItem{
					{
						PLMNID: context.PLMNID{
							Mcc: "208",
							Mnc: "93",
						},
						TAISliceSupportList: []context.SliceSupportItem{
							{
								SNSSAI: context.SNSSAIItem{
									SST: "01",
									SD:  "010203",
								},
							},
						},
					},
				},
			},
		},
	}
	tngfSelf.GTPBindAddress = "10.0.0.1"
}

func testTNGFUe() *context.TNGFUe {
	return &context.TNGFUe{
		RanUeNgapId:           123,
		AmfUeNgapId:           456,
		IPAddrv4:              "192.0.2.1",
		TNAPID:                0x0102030405060708,
		RRCEstablishmentCause: 3,
	}
}

func testPDUSession() *context.PDUSession {
	return &context.PDUSession{
		Id: 10,
		GTPConnection: &context.GTPConnectionInfo{
			IncomingTEID: 0x01020304,
		},
		QFIList: []uint8{1, 9},
	}
}

func testCause() ngapType.Cause {
	return ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentUserInactivity,
		},
	}
}
