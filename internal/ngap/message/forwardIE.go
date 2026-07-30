package message

import (
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
)

func AppendPDUSessionResourceSetupListCxtRes(
	list *ie.PDUSessionResourceSetupListCxtRes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceSetupItemCxtRes{
		PDUSessionID:                            &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupResponseTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceFailedToSetupListCxtRes(
	list *ie.PDUSessionResourceFailedToSetupListCxtRes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceFailedToSetupItemCxtRes{
		PDUSessionID: &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupUnsuccessfulTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceFailedToSetupListCxtfail(
	list *ie.PDUSessionResourceFailedToSetupListCxtFail, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceFailedToSetupItemCxtFail{
		PDUSessionID: &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupUnsuccessfulTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceSetupListSURes(
	list *ie.PDUSessionResourceSetupListSURes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceSetupItemSURes{
		PDUSessionID:                            &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupResponseTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceFailedToSetupListSURes(
	list *ie.PDUSessionResourceFailedToSetupListSURes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceFailedToSetupItemSURes{
		PDUSessionID: &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupUnsuccessfulTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceModifyListModRes(
	list *ie.PDUSessionResourceModifyListModRes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceModifyItemModRes{
		PDUSessionID:                             &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceModifyResponseTransfer: &encodedTransfer,
	})
}

func AppendPDUSessionResourceFailedToModifyListModRes(
	list *ie.PDUSessionResourceFailedToModifyListModRes, pduSessionID int64, transfer []byte,
) {
	encodedTransfer := aper.OctetString(transfer)
	list.List = append(list.List, ie.PDUSessionResourceFailedToModifyItemModRes{
		PDUSessionID: &ie.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceModifyUnsuccessfulTransfer: &encodedTransfer,
	})
}
