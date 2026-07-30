package context

import (
	"bytes"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/sctp"
)

type TNGFAMF struct {
	SCTPAddr              string
	SCTPConn              *sctp.SCTPConn
	AMFName               *ie.AMFName
	ServedGUAMIList       *ie.ServedGUAMIList
	RelativeAMFCapacity   *ie.RelativeAMFCapacity
	PLMNSupportList       *ie.PLMNSupportList
	AMFTNLAssociationList map[string]*AMFTNLAssociationItem // v4+v6 as key
	// Overload related
	AMFOverloadContent *AMFOverloadContent
	// Relative Context
	TngfUeList map[int64]*TNGFUe // ranUeNgapId as key
}

type AMFTNLAssociationItem struct {
	Ipv4                   string
	Ipv6                   string
	TNLAssociationUsage    *ie.TNLAssociationUsage
	TNLAddressWeightFactor *int64
}

type AMFOverloadContent struct {
	Action     *ie.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}

type SliceOverloadItem struct {
	SNssaiList []ie.SNSSAI
	Action     *ie.OverloadAction
	TrafficInd *int64
}

func (amf *TNGFAMF) init(sctpAddr string, conn *sctp.SCTPConn) {
	amf.SCTPAddr = sctpAddr
	amf.SCTPConn = conn
	amf.AMFTNLAssociationList = make(map[string]*AMFTNLAssociationItem)
	amf.TngfUeList = make(map[int64]*TNGFUe)
}

func (amf *TNGFAMF) FindUeByAmfUeNgapID(id int64) *TNGFUe {
	for _, tngfUe := range amf.TngfUeList {
		if tngfUe.AmfUeNgapId == id {
			return tngfUe
		}
	}
	return nil
}

func (amf *TNGFAMF) RemoveAllRelatedUe() {
	for _, ue := range amf.TngfUeList {
		ue.Remove()
	}
}

func (amf *TNGFAMF) AddAMFTNLAssociationItem(info ie.CPTransportLayerInformation) *AMFTNLAssociationItem {
	address, ok := info.Choice.(*ie.TransportLayerAddress)
	if !ok {
		return nil
	}

	item := &AMFTNLAssociationItem{}
	item.Ipv4, item.Ipv6 = transportLayerAddressToIPStrings(address)
	amf.AMFTNLAssociationList[item.Ipv4+item.Ipv6] = item
	return item
}

func (amf *TNGFAMF) FindAMFTNLAssociationItem(info ie.CPTransportLayerInformation) *AMFTNLAssociationItem {
	address, ok := info.Choice.(*ie.TransportLayerAddress)
	if !ok {
		return nil
	}

	v4, v6 := transportLayerAddressToIPStrings(address)
	return amf.AMFTNLAssociationList[v4+v6]
}

func (amf *TNGFAMF) DeleteAMFTNLAssociationItem(info ie.CPTransportLayerInformation) {
	address, ok := info.Choice.(*ie.TransportLayerAddress)
	if !ok {
		return
	}

	v4, v6 := transportLayerAddressToIPStrings(address)
	delete(amf.AMFTNLAssociationList, v4+v6)
}

func (amf *TNGFAMF) StartOverload(
	resp *ie.OverloadResponse, trafloadInd *ie.TrafficLoadReductionIndication,
	nssai *ie.OverloadStartNSSAIList,
) *AMFOverloadContent {
	if resp == nil && trafloadInd == nil && nssai == nil {
		return nil
	}
	content := AMFOverloadContent{}
	if resp != nil {
		content.Action = overloadAction(resp)
	}
	if trafloadInd != nil {
		content.TrafficInd = &trafloadInd.Value
	}
	if nssai != nil {
		for _, item := range nssai.List {
			sliceItem := SliceOverloadItem{}
			if item.SliceOverloadList != nil {
				for _, item2 := range item.SliceOverloadList.List {
					if item2.SNSSAI != nil {
						sliceItem.SNssaiList = append(sliceItem.SNssaiList, *item2.SNSSAI)
					}
				}
			}
			if item.SliceOverloadResponse != nil {
				sliceItem.Action = overloadAction(item.SliceOverloadResponse)
			}
			if item.SliceTrafficLoadReductionIndication != nil {
				sliceItem.TrafficInd = &item.SliceTrafficLoadReductionIndication.Value
			}
			content.NSSAIList = append(content.NSSAIList, sliceItem)
		}
	}
	amf.AMFOverloadContent = &content
	return amf.AMFOverloadContent
}

func (amf *TNGFAMF) StopOverload() {
	amf.AMFOverloadContent = nil
}

// FindAvalibleAMFByCompareGUAMI compares the incoming GUAMI with AMF served GUAMI
// and return if this AMF is avalible for UE
func (amf *TNGFAMF) FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI *ie.GUAMI) bool {
	for _, amfServedGUAMI := range amf.ServedGUAMIList.List {
		if !equalGUAMI(amfServedGUAMI.GUAMI, ueSpecifiedGUAMI) {
			continue
		}
		return true
	}
	return false
}

func (amf *TNGFAMF) FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedSelectedPLMNId *ie.PLMNIdentity) bool {
	for _, amfServedPLMNId := range amf.PLMNSupportList.List {
		if amfServedPLMNId.PLMNIdentity == nil || ueSpecifiedSelectedPLMNId == nil {
			continue
		}
		if !bytes.Equal(amfServedPLMNId.PLMNIdentity.Value, ueSpecifiedSelectedPLMNId.Value) {
			continue
		}
		return true
	}
	return false
}

func overloadAction(response *ie.OverloadResponse) *ie.OverloadAction {
	if response == nil {
		return nil
	}

	action, _ := response.Choice.(*ie.OverloadAction)
	return action
}

func equalGUAMI(first, second *ie.GUAMI) bool {
	if first == nil || second == nil {
		return false
	}

	firstData := aper.NewPerBitData(nil)
	if err := first.Write(firstData); err != nil {
		return false
	}
	secondData := aper.NewPerBitData(nil)
	if err := second.Write(secondData); err != nil {
		return false
	}

	return bytes.Equal(firstData.Bytes(), secondData.Bytes())
}
