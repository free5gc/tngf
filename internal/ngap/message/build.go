package message

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/tngf/internal/util"
	"github.com/free5gc/tngf/pkg/context"
)

var errBuilderNotImplemented = errors.New("NGAP message builder is not implemented")

func BuildNGSetupRequest() ([]byte, error) {
	tngfSelf := context.TNGFSelf()
	supportedTAList, err := buildSupportedTAList(tngfSelf.NFInfo.SupportedTAList)
	if err != nil {
		return nil, err
	}

	plmn := util.PlmnIdToNgap(tngfSelf.NFInfo.GlobalTNGFID.PLMNID)
	globalRANNodeID := &ie.GlobalRANNodeID{
		Choice: &ie.ProtocolIESingleContainerGlobalRANNodeIDExtIEs{
			GlobalRANNodeIDExtIEs: ie.GlobalRANNodeIDExtIEs{
				GlobalTNGFID: &ie.GlobalTNGFID{
					PLMNIdentity: &plmn,
					TNGFID: &ie.TNGFID{
						Choice: &ie.TNGFIDForTNGFID{Value: *util.TngfIdToNgap(tngfSelf.NFInfo.GlobalTNGFID.TNGFID)},
					},
				},
			},
		},
	}

	return (&ngapMessage.NGSetupRequest{
		GlobalRANNodeID:  globalRANNodeID,
		RANNodeName:      &ie.RANNodeName{Value: aper.PrintableString(tngfSelf.NFInfo.RanNodeName)},
		SupportedTAList:  supportedTAList,
		DefaultPagingDRX: &ie.PagingDRX{Value: ie.PagingDRXPresentV128},
	}).MarshalBinary()
}

func BuildNGReset(ie.Cause, *ie.UEAssociatedLogicalNGConnectionList) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeNGReset
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNGReset
	// 	initiatingMessage.Value.NGReset = new(ngapType.NGReset)
	//
	// 	nGReset := initiatingMessage.Value.NGReset
	// 	nGResetIEs := &nGReset.ProtocolIEs
	// 	// Cause
	// 	{
	// 		ie := ngapType.NGResetIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCause
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.NGResetIEsPresentCause
	// 		ie.Value.Cause = new(ngapType.Cause)
	//
	// 		cause := ie.Value.Cause
	// 		*cause = ngCause
	//
	// 		nGResetIEs.List = append(nGResetIEs.List, ie)
	// 	}
	// 	// ResetType
	// 	{
	// 		ie := ngapType.NGResetIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDResetType
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.NGResetIEsPresentResetType
	// 		ie.Value.ResetType = new(ngapType.ResetType)
	//
	// 		resetType := ie.Value.ResetType
	// 		if partOfNGInterface == nil {
	// 			resetType.Present = ngapType.ResetTypePresentNGInterface
	// 			resetType.NGInterface = new(ngapType.ResetAll)
	// 			resetType.NGInterface.Value = ngapType.ResetAllPresentResetAll
	// 		} else {
	// 			resetType.Present = ngapType.ResetTypePresentPartOfNGInterface
	// 			resetType.PartOfNGInterface = new(ngapType.UEAssociatedLogicalNGConnectionList)
	// 			resetType.PartOfNGInterface = partOfNGInterface
	// 		}
	//
	// 		nGResetIEs.List = append(nGResetIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildNGResetAcknowledge(*ie.UEAssociatedLogicalNGConnectionList, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeNGReset
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentNGResetAcknowledge
	// 	successfulOutcome.Value.NGResetAcknowledge = new(ngapType.NGResetAcknowledge)
	//
	// 	nGResetAcknowledge := successfulOutcome.Value.NGResetAcknowledge
	// 	nGResetAcknowledgeIEs := &nGResetAcknowledge.ProtocolIEs
	// 	// UEAssociatedLogicalNGConnectionList
	// 	if partOfNGInterface != nil {
	// 		ie := ngapType.NGResetAcknowledgeIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.NGResetAcknowledgeIEsPresentUEAssociatedLogicalNGConnectionList
	// 		ie.Value.UEAssociatedLogicalNGConnectionList = new(ngapType.UEAssociatedLogicalNGConnectionList)
	//
	// 		uEAssociatedLogicalNGConnectionList := ie.Value.UEAssociatedLogicalNGConnectionList
	// 		*uEAssociatedLogicalNGConnectionList = *partOfNGInterface
	//
	// 		nGResetAcknowledgeIEs.List = append(nGResetAcknowledgeIEs.List, ie)
	// 	}
	// 	// CriticalityDiagnostics
	// 	if diagnostics != nil {
	// 		ie := ngapType.NGResetAcknowledgeIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.NGResetAcknowledgeIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = new(ngapType.CriticalityDiagnostics)
	//
	// 		criticalityDiagnostics := ie.Value.CriticalityDiagnostics
	// 		*criticalityDiagnostics = *diagnostics
	//
	// 		nGResetAcknowledgeIEs.List = append(nGResetAcknowledgeIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildInitialContextSetupResponse(
	ue *context.TNGFUe,
	responseList *ie.PDUSessionResourceSetupListCxtRes,
	failedList *ie.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ie.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.InitialContextSetupResponse{
		AMFUENGAPID:                       &ie.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                       &ie.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceSetupListCxtRes: responseList,
		PDUSessionResourceFailedToSetupListCxtRes: failedList,
		CriticalityDiagnostics:                    criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildInitialContextSetupFailure(
	*context.TNGFUe, ie.Cause, *ie.PDUSessionResourceFailedToSetupListCxtFail, *ie.CriticalityDiagnostics,
) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	// 	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)
	//
	// 	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	// 	unsuccessfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	// 	unsuccessfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	unsuccessfulOutcome.Value.Present = ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure
	// 	unsuccessfulOutcome.Value.InitialContextSetupFailure = new(ngapType.InitialContextSetupFailure)
	//
	// 	initialContextSetupFailure := unsuccessfulOutcome.Value.InitialContextSetupFailure
	// 	initialContextSetupFailureIEs := &initialContextSetupFailure.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.InitialContextSetupFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.InitialContextSetupFailureIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 	aMFUENGAPID := ie.Value.AMFUENGAPID
	// 	aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 	initialContextSetupFailureIEs.List = append(initialContextSetupFailureIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.InitialContextSetupFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.InitialContextSetupFailureIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 	rANUENGAPID := ie.Value.RANUENGAPID
	// 	rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 	initialContextSetupFailureIEs.List = append(initialContextSetupFailureIEs.List, ie)
	//
	// 	// PDU Session Resource Failed to Setup List
	// 	if failedList != nil && len(failedList.List) > 0 {
	// 		ie = ngapType.InitialContextSetupFailureIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListCxtFail
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.InitialContextSetupFailureIEsPresentPDUSessionResourceFailedToSetupListCxtFail
	// 		ie.Value.PDUSessionResourceFailedToSetupListCxtFail = failedList
	// 		initialContextSetupFailureIEs.List = append(initialContextSetupFailureIEs.List, ie)
	// 	}
	//
	// 	// Cause
	// 	ie = ngapType.InitialContextSetupFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDCause
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.InitialContextSetupFailureIEsPresentCause
	// 	ie.Value.Cause = &cause
	// 	initialContextSetupFailureIEs.List = append(initialContextSetupFailureIEs.List, ie)
	//
	// 	// Criticality Diagnostics (optional)
	// 	if criticalityDiagnostics != nil {
	// 		ie = ngapType.InitialContextSetupFailureIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 		initialContextSetupFailureIEs.List = append(initialContextSetupFailureIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildUEContextModificationResponse(*context.TNGFUe, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeUEContextModification
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentUEContextModificationResponse
	// 	successfulOutcome.Value.UEContextModificationResponse = new(ngapType.UEContextModificationResponse)
	//
	// 	uEContextModificationResponse := successfulOutcome.Value.UEContextModificationResponse
	// 	uEContextModificationResponseIEs := &uEContextModificationResponse.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.UEContextModificationResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextModificationResponseIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 	aMFUENGAPID := ie.Value.AMFUENGAPID
	// 	aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 	uEContextModificationResponseIEs.List = append(uEContextModificationResponseIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.UEContextModificationResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextModificationResponseIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 	rANUENGAPID := ie.Value.RANUENGAPID
	// 	rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 	uEContextModificationResponseIEs.List = append(uEContextModificationResponseIEs.List, ie)
	//
	// 	// Criticality Diagnostics (optional)
	// 	ie = ngapType.UEContextModificationResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 	uEContextModificationResponseIEs.List = append(uEContextModificationResponseIEs.List, ie)
	//
	return nil, errBuilderNotImplemented
}

func BuildUEContextModificationFailure(*context.TNGFUe, ie.Cause, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	// 	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)
	//
	// 	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	// 	unsuccessfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeUEContextModification
	// 	unsuccessfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	unsuccessfulOutcome.Value.Present = ngapType.UnsuccessfulOutcomePresentUEContextModificationFailure
	// 	unsuccessfulOutcome.Value.UEContextModificationFailure = new(ngapType.UEContextModificationFailure)
	//
	// 	uEContextModificationFailure := unsuccessfulOutcome.Value.UEContextModificationFailure
	// 	uEContextModificationFailureIEs := &uEContextModificationFailure.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.UEContextModificationFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextModificationFailureIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 	aMFUENGAPID := ie.Value.AMFUENGAPID
	// 	aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 	uEContextModificationFailureIEs.List = append(uEContextModificationFailureIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.UEContextModificationFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextModificationFailureIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 	rANUENGAPID := ie.Value.RANUENGAPID
	// 	rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 	uEContextModificationFailureIEs.List = append(uEContextModificationFailureIEs.List, ie)
	//
	// 	// Cause
	// 	ie = ngapType.UEContextModificationFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDCause
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextModificationFailureIEsPresentCause
	// 	ie.Value.Cause = &cause
	// 	uEContextModificationFailureIEs.List = append(uEContextModificationFailureIEs.List, ie)
	//
	// 	// Criticality Diagnostics (optional)
	// 	ie = ngapType.UEContextModificationFailureIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 	uEContextModificationFailureIEs.List = append(uEContextModificationFailureIEs.List, ie)
	//
	return nil, errBuilderNotImplemented
}

func BuildUEContextReleaseComplete(*context.TNGFUe, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeUEContextRelease
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentUEContextReleaseComplete
	// 	successfulOutcome.Value.UEContextReleaseComplete = new(ngapType.UEContextReleaseComplete)
	//
	// 	uEContextReleaseComplete := successfulOutcome.Value.UEContextReleaseComplete
	// 	uEContextReleaseCompleteIEs := &uEContextReleaseComplete.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.UEContextReleaseCompleteIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 	aMFUENGAPID := ie.Value.AMFUENGAPID
	// 	aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.UEContextReleaseCompleteIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 	rANUENGAPID := ie.Value.RANUENGAPID
	// 	rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	//
	// 	// User Location Information (optional)
	// 	ie = ngapType.UEContextReleaseCompleteIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentUserLocationInformation
	// 	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)
	//
	// 	userLocationInformation := ie.Value.UserLocationInformation
	// 	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationTNGF
	// 	userLocationInformation.UserLocationInformationTNGF = new(ngapType.UserLocationInformationTNGF)
	//
	// 	userLocationInfoTNGF := userLocationInformation.UserLocationInformationTNGF
	// 	userLocationInfoTNGF.IPAddress = ngapConvert.IPAddressToNgap(ue.IPAddrv4, ue.IPAddrv6)
	// 	userLocationInfoTNGF.PortNumber = ngapConvert.PortNumberToNgap(ue.PortNumber)
	//
	// 	uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	//
	// 	// PDU Session Resource List (optional)
	// 	if len(ue.PduSessionList) > 0 {
	// 		ie = ngapType.UEContextReleaseCompleteIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListCxtRelCpl
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentPDUSessionResourceListCxtRelCpl
	// 		ie.Value.PDUSessionResourceListCxtRelCpl = new(ngapType.PDUSessionResourceListCxtRelCpl)
	//
	// 		pDUSessionResourceListCxtRelCpl := ie.Value.PDUSessionResourceListCxtRelCpl
	//
	// 		// PDU Session Resource Item (in PDU Session Resource List)
	// 		for _, pduSession := range ue.PduSessionList {
	// 			pDUSessionResourceItemCxtRelCpl := ngapType.PDUSessionResourceItemCxtRelCpl{}
	// 			pDUSessionResourceItemCxtRelCpl.PDUSessionID.Value = pduSession.Id
	// 			pDUSessionResourceListCxtRelCpl.List = append(pDUSessionResourceListCxtRelCpl.List,
	// 				pDUSessionResourceItemCxtRelCpl)
	// 		}
	//
	// 		uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	// 	}
	//
	// 	// Criticality Diagnostics (optional)
	// 	if criticalityDiagnostics != nil {
	// 		ie = ngapType.UEContextReleaseCompleteIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 		uEContextReleaseCompleteIEs.List = append(uEContextReleaseCompleteIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildUEContextReleaseRequest(*context.TNGFUe, ie.Cause) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeUEContextReleaseRequest
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUEContextReleaseRequest
	// 	initiatingMessage.Value.UEContextReleaseRequest = new(ngapType.UEContextReleaseRequest)
	//
	// 	uEContextReleaseRequest := initiatingMessage.Value.UEContextReleaseRequest
	// 	uEContextReleaseRequestIEs := &uEContextReleaseRequest.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.UEContextReleaseRequestIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 	aMFUENGAPID := ie.Value.AMFUENGAPID
	// 	aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.UEContextReleaseRequestIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 	rANUENGAPID := ie.Value.RANUENGAPID
	// 	rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)
	//
	// 	// PDU Session Resource List
	// 	ie = ngapType.UEContextReleaseRequestIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListCxtRelReq
	// 	ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentPDUSessionResourceListCxtRelReq
	// 	ie.Value.PDUSessionResourceListCxtRelReq = new(ngapType.PDUSessionResourceListCxtRelReq)
	//
	// 	pDUSessionResourceListCxtRelReq := ie.Value.PDUSessionResourceListCxtRelReq
	//
	// 	// PDU Session Resource Item in PDU session Resource List
	// 	for _, pduSession := range ue.PduSessionList {
	// 		pDUSessionResourceItem := ngapType.PDUSessionResourceItemCxtRelReq{}
	// 		pDUSessionResourceItem.PDUSessionID.Value = pduSession.Id
	// 		pDUSessionResourceListCxtRelReq.List = append(pDUSessionResourceListCxtRelReq.List,
	// 			pDUSessionResourceItem)
	// 	}
	// 	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)
	//
	// 	// Cause
	// 	ie = ngapType.UEContextReleaseRequestIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDCause
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentCause
	// 	ie.Value.Cause = &cause
	// 	uEContextReleaseRequestIEs.List = append(uEContextReleaseRequestIEs.List, ie)
	//
	return nil, errBuilderNotImplemented
}

func BuildInitialUEMessage(
	ue *context.TNGFUe, nasPdu []byte, allowedNSSAI *ie.AllowedNSSAI,
) ([]byte, error) {
	userLocationInformation, err := buildUserLocationInformation(ue)
	if err != nil {
		return nil, err
	}

	message := &ngapMessage.InitialUEMessage{
		RANUENGAPID:             &ie.RANUENGAPID{Value: ue.RanUeNgapId},
		NASPDU:                  &ie.NASPDU{Value: nasPdu},
		UserLocationInformation: userLocationInformation,
		RRCEstablishmentCause:   &ie.RRCEstablishmentCause{Value: aper.Enumerated(ue.RRCEstablishmentCause)},
		UEContextRequest:        &ie.UEContextRequest{Value: ie.UEContextRequestPresentRequested},
		AllowedNSSAI:            allowedNSSAI,
	}

	if ue.Guti != "" {
		amfID, tmsi, err := splitGUTI(ue.Guti)
		if err != nil {
			return nil, err
		}
		amfSetID, amfPointer, err := amfIDToNGAP(amfID)
		if err != nil {
			return nil, err
		}
		tmsiBytes, err := hex.DecodeString(tmsi)
		if err != nil {
			return nil, fmt.Errorf("decode 5G-TMSI: %w", err)
		}
		message.FiveGSTMSI = &ie.FiveGSTMSI{
			AMFSetID:   &ie.AMFSetID{Value: amfSetID},
			AMFPointer: &ie.AMFPointer{Value: amfPointer},
			FiveGTMSI:  &ie.FiveGTMSI{Value: tmsiBytes},
		}
		message.AMFSetID = &ie.AMFSetID{Value: amfSetID}
	}

	return message.MarshalBinary()
}

func BuildUplinkNASTransport(ue *context.TNGFUe, nasPdu []byte) ([]byte, error) {
	userLocationInformation, err := buildUserLocationInformation(ue)
	if err != nil {
		return nil, err
	}

	return (&ngapMessage.UplinkNASTransport{
		AMFUENGAPID:             &ie.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:             &ie.RANUENGAPID{Value: ue.RanUeNgapId},
		NASPDU:                  &ie.NASPDU{Value: nasPdu},
		UserLocationInformation: userLocationInformation,
	}).MarshalBinary()
}

func BuildNASNonDeliveryIndication(*context.TNGFUe, []byte, ie.Cause) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeNASNonDeliveryIndication
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNASNonDeliveryIndication
	// 	initiatingMessage.Value.NASNonDeliveryIndication = new(ngapType.NASNonDeliveryIndication)
	//
	// 	nASNonDeliveryIndication := initiatingMessage.Value.NASNonDeliveryIndication
	// 	nASNonDeliveryIndicationIEs := &nASNonDeliveryIndication.ProtocolIEs
	// 	// AMFUENGAPID
	// 	{
	// 		ie := ngapType.NASNonDeliveryIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.NASNonDeliveryIndicationIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 		aMFUENGAPID := ie.Value.AMFUENGAPID
	// 		aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 		nASNonDeliveryIndicationIEs.List = append(nASNonDeliveryIndicationIEs.List, ie)
	// 	}
	// 	// RANUENGAPID
	// 	{
	// 		ie := ngapType.NASNonDeliveryIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.NASNonDeliveryIndicationIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 		rANUENGAPID := ie.Value.RANUENGAPID
	// 		rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 		nASNonDeliveryIndicationIEs.List = append(nASNonDeliveryIndicationIEs.List, ie)
	// 	}
	// 	// NASPDU
	// 	{
	// 		ie := ngapType.NASNonDeliveryIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.NASNonDeliveryIndicationIEsPresentNASPDU
	// 		ie.Value.NASPDU = new(ngapType.NASPDU)
	//
	// 		nASPDU := ie.Value.NASPDU
	// 		nASPDU.Value = nasPdu
	// 		nASNonDeliveryIndicationIEs.List = append(nASNonDeliveryIndicationIEs.List, ie)
	// 	}
	// 	// Cause
	// 	{
	// 		ie := ngapType.NASNonDeliveryIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCause
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.NASNonDeliveryIndicationIEsPresentCause
	// 		ie.Value.Cause = new(ngapType.Cause)
	//
	// 		ie.Value.Cause = &cause
	//
	// 		nASNonDeliveryIndicationIEs.List = append(nASNonDeliveryIndicationIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildRerouteNASRequest() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildPDUSessionResourceSetupResponse(
	ue *context.TNGFUe,
	responseList *ie.PDUSessionResourceSetupListSURes,
	failedList *ie.PDUSessionResourceFailedToSetupListSURes,
	criticalityDiagnostics *ie.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.PDUSessionResourceSetupResponse{
		AMFUENGAPID:                              &ie.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                              &ie.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceSetupListSURes:         responseList,
		PDUSessionResourceFailedToSetupListSURes: failedList,
		CriticalityDiagnostics:                   criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildPDUSessionResourceModifyResponse(
	*context.TNGFUe, *ie.PDUSessionResourceModifyListModRes, *ie.PDUSessionResourceFailedToModifyListModRes,
	*ie.CriticalityDiagnostics,
) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceModify
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceModifyResponse
	// 	successfulOutcome.Value.PDUSessionResourceModifyResponse = new(ngapType.PDUSessionResourceModifyResponse)
	//
	// 	pduSessionResourceModifyResponse := successfulOutcome.Value.PDUSessionResourceModifyResponse
	// 	pduSessionResourceModifyResponseIEs := &pduSessionResourceModifyResponse.ProtocolIEs
	//
	// 	// AMF UE NGAP ID
	// 	ie := ngapType.PDUSessionResourceModifyResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.PDUSessionResourceModifyResponseIEsPresentAMFUENGAPID
	// 	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{
	// 		Value: ue.AmfUeNgapId,
	// 	}
	// 	pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	//
	// 	// RAN UE NGAP ID
	// 	ie = ngapType.PDUSessionResourceModifyResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.PDUSessionResourceModifyResponseIEsPresentRANUENGAPID
	// 	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{
	// 		Value: ue.RanUeNgapId,
	// 	}
	// 	pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	//
	// 	// PDU Session Resource Modify Response List (optional)
	// 	if responseList != nil && len(responseList.List) > 0 {
	// 		ie = ngapType.PDUSessionResourceModifyResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceModifyListModRes
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceModifyResponseIEsPresentPDUSessionResourceModifyListModRes
	// 		ie.Value.PDUSessionResourceModifyListModRes = responseList
	// 		pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	// 	}
	//
	// 	// PDU Session Resource Failed to Modify List (optional)
	// 	if failedList != nil && len(failedList.List) > 0 {
	// 		ie = ngapType.PDUSessionResourceModifyResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToModifyListModRes
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceModifyResponseIEsPresentPDUSessionResourceFailedToModifyListModRes
	// 		ie.Value.PDUSessionResourceFailedToModifyListModRes = failedList
	// 		pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	// 	}
	//
	// 	// User Location Information
	// 	ie = ngapType.PDUSessionResourceModifyResponseIEs{}
	// 	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	ie.Value.Present = ngapType.PDUSessionResourceModifyResponseIEsPresentUserLocationInformation
	// 	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)
	//
	// 	userLocationInformation := ie.Value.UserLocationInformation
	// 	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationTNGF
	// 	userLocationInformation.UserLocationInformationTNGF = new(ngapType.UserLocationInformationTNGF)
	//
	// 	userLocationInformationTNGF := userLocationInformation.UserLocationInformationTNGF
	// 	userLocationInformationTNGF.IPAddress = ngapConvert.IPAddressToNgap(ue.IPAddrv4, ue.IPAddrv6)
	// 	userLocationInformationTNGF.PortNumber = ngapConvert.PortNumberToNgap(ue.PortNumber)
	//
	// 	pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	//
	// 	// Criticality Diagnostics (optional)
	// 	if criticalityDiagnostics != nil {
	// 		ie = ngapType.PDUSessionResourceModifyResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 		pduSessionResourceModifyResponseIEs.List = append(pduSessionResourceModifyResponseIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildPDUSessionResourceModifyIndication(*context.TNGFUe, []ie.PDUSessionResourceModifyItemModInd) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceModifyIndication
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPDUSessionResourceModifyIndication
	// 	initiatingMessage.Value.PDUSessionResourceModifyIndication = new(ngapType.PDUSessionResourceModifyIndication)
	//
	// 	pDUSessionResourceModifyIndication := initiatingMessage.Value.PDUSessionResourceModifyIndication
	// 	pDUSessionResourceModifyIndicationIEs := &pDUSessionResourceModifyIndication.ProtocolIEs
	// 	// AMFUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceModifyIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 		aMFUENGAPID := ie.Value.AMFUENGAPID
	// 		aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 		pDUSessionResourceModifyIndicationIEs.List = append(pDUSessionResourceModifyIndicationIEs.List, ie)
	// 	}
	// 	// RANUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceModifyIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 		rANUENGAPID := ie.Value.RANUENGAPID
	// 		rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 		pDUSessionResourceModifyIndicationIEs.List = append(pDUSessionResourceModifyIndicationIEs.List, ie)
	// 	}
	// 	// PDUSessionResourceModifyListModInd
	// 	{
	// 		ie := ngapType.PDUSessionResourceModifyIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceModifyListModInd
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceModifyIndicationIEsPresentPDUSessionResourceModifyListModInd
	// 		ie.Value.PDUSessionResourceModifyListModInd = new(ngapType.PDUSessionResourceModifyListModInd)
	//
	// 		pDUSessionResourceModifyListModInd := ie.Value.PDUSessionResourceModifyListModInd
	// 		pDUSessionResourceModifyListModInd.List = modifyList
	//
	// 		pDUSessionResourceModifyIndicationIEs.List = append(pDUSessionResourceModifyIndicationIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildPDUSessionResourceNotify(
	*context.TNGFUe, *ie.PDUSessionResourceNotifyList, *ie.PDUSessionResourceReleasedListNot,
) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceNotify
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPDUSessionResourceNotify
	// 	initiatingMessage.Value.PDUSessionResourceNotify = new(ngapType.PDUSessionResourceNotify)
	//
	// 	pDUSessionResourceNotify := initiatingMessage.Value.PDUSessionResourceNotify
	// 	pDUSessionResourceNotifyIEs := &pDUSessionResourceNotify.ProtocolIEs
	// 	// AMFUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceNotifyIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceNotifyIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 		aMFUENGAPID := ie.Value.AMFUENGAPID
	// 		aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 		pDUSessionResourceNotifyIEs.List = append(pDUSessionResourceNotifyIEs.List, ie)
	// 	}
	// 	// RANUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceNotifyIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceNotifyIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 		rANUENGAPID := ie.Value.RANUENGAPID
	// 		rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 		pDUSessionResourceNotifyIEs.List = append(pDUSessionResourceNotifyIEs.List, ie)
	// 	}
	// 	// PDUSessionResourceNotifyList
	// 	if notiList != nil {
	// 		ie := ngapType.PDUSessionResourceNotifyIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceNotifyList
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.PDUSessionResourceNotifyIEsPresentPDUSessionResourceNotifyList
	// 		ie.Value.PDUSessionResourceNotifyList = new(ngapType.PDUSessionResourceNotifyList)
	//
	// 		pDUSessionResourceNotifyList := ie.Value.PDUSessionResourceNotifyList
	// 		*pDUSessionResourceNotifyList = *notiList
	//
	// 		pDUSessionResourceNotifyIEs.List = append(pDUSessionResourceNotifyIEs.List, ie)
	// 	}
	// 	// PDUSessionResourceReleasedListNot
	// 	if relList != nil {
	// 		ie := ngapType.PDUSessionResourceNotifyIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceReleasedListNot
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceNotifyIEsPresentPDUSessionResourceReleasedListNot
	// 		ie.Value.PDUSessionResourceReleasedListNot = new(ngapType.PDUSessionResourceReleasedListNot)
	//
	// 		pDUSessionResourceReleasedListNot := ie.Value.PDUSessionResourceReleasedListNot
	// 		*pDUSessionResourceReleasedListNot = *relList
	//
	// 		pDUSessionResourceNotifyIEs.List = append(pDUSessionResourceNotifyIEs.List, ie)
	// 	}
	// 	// UserLocationInformation
	// 	if (ue.IPAddrv4 != "" || ue.IPAddrv6 != "") && ue.PortNumber != 0 {
	// 		ie := ngapType.PDUSessionResourceNotifyIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceNotifyIEsPresentUserLocationInformation
	// 		ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)
	//
	// 		userLocationInformation := ie.Value.UserLocationInformation
	// 		*userLocationInformation = ngapType.UserLocationInformation{
	// 			Present: ngapType.UserLocationInformationPresentUserLocationInformationTNGF,
	// 			UserLocationInformationTNGF: &ngapType.UserLocationInformationTNGF{
	// 				IPAddress:  ngapConvert.IPAddressToNgap(ue.IPAddrv4, ue.IPAddrv6),
	// 				PortNumber: ngapConvert.PortNumberToNgap(ue.PortNumber),
	// 			},
	// 		}
	//
	// 		pDUSessionResourceNotifyIEs.List = append(pDUSessionResourceNotifyIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildPDUSessionResourceReleaseResponse(
	*context.TNGFUe, ie.PDUSessionResourceReleasedListRelRes, *ie.CriticalityDiagnostics,
) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceRelease
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceReleaseResponse
	// 	successfulOutcome.Value.PDUSessionResourceReleaseResponse = new(ngapType.PDUSessionResourceReleaseResponse)
	//
	// 	pDUSessionResourceReleaseResponse := successfulOutcome.Value.PDUSessionResourceReleaseResponse
	// 	pDUSessionResourceReleaseResponseIEs := &pDUSessionResourceReleaseResponse.ProtocolIEs
	// 	// AMFUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 		aMFUENGAPID := ie.Value.AMFUENGAPID
	// 		aMFUENGAPID.Value = ue.AmfUeNgapId
	//
	// 		pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)
	// 	}
	// 	// RANUENGAPID
	// 	{
	// 		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 		rANUENGAPID := ie.Value.RANUENGAPID
	// 		rANUENGAPID.Value = ue.RanUeNgapId
	//
	// 		pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)
	// 	}
	// 	// PDUSessionResourceReleasedListRelRes
	// 	{
	// 		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceReleasedListRelRes
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentPDUSessionResourceReleasedListRelRes
	// 		ie.Value.PDUSessionResourceReleasedListRelRes = new(ngapType.PDUSessionResourceReleasedListRelRes)
	//
	// 		pDUSessionResourceReleasedListRelRes := ie.Value.PDUSessionResourceReleasedListRelRes
	// 		*pDUSessionResourceReleasedListRelRes = relList
	//
	// 		pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)
	// 	}
	// 	// UserLocationInformation
	// 	if (ue.IPAddrv4 != "" || ue.IPAddrv6 != "") && ue.PortNumber != 0 {
	// 		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentUserLocationInformation
	// 		ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)
	//
	// 		userLocationInformation := ie.Value.UserLocationInformation
	// 		*userLocationInformation = ngapType.UserLocationInformation{
	// 			Present: ngapType.UserLocationInformationPresentUserLocationInformationTNGF,
	// 			UserLocationInformationTNGF: &ngapType.UserLocationInformationTNGF{
	// 				IPAddress:  ngapConvert.IPAddressToNgap(ue.IPAddrv4, ue.IPAddrv6),
	// 				PortNumber: ngapConvert.PortNumberToNgap(ue.PortNumber),
	// 			},
	// 		}
	//
	// 		pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)
	// 	}
	// 	// CriticalityDiagnostics
	// 	if diagnostics != nil {
	// 		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = new(ngapType.CriticalityDiagnostics)
	//
	// 		criticalityDiagnostics := ie.Value.CriticalityDiagnostics
	// 		*criticalityDiagnostics = *diagnostics
	//
	// 		pDUSessionResourceReleaseResponseIEs.List = append(pDUSessionResourceReleaseResponseIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildErrorIndication(*int64, *int64, *ie.Cause, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeErrorIndication
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentErrorIndication
	// 	initiatingMessage.Value.ErrorIndication = new(ngapType.ErrorIndication)
	//
	// 	errorIndication := initiatingMessage.Value.ErrorIndication
	// 	errorIndicationIEs := &errorIndication.ProtocolIEs
	//
	// 	if amfUENGAPID != nil && ranUENGAPID != nil {
	// 		// AMF UE NGAP ID
	// 		ie := ngapType.ErrorIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.ErrorIndicationIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *amfUENGAPID}
	// 		errorIndicationIEs.List = append(errorIndicationIEs.List, ie)
	//
	// 		// RAN UE NGAP ID
	// 		ie = ngapType.ErrorIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.ErrorIndicationIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: *ranUENGAPID}
	// 		errorIndicationIEs.List = append(errorIndicationIEs.List, ie)
	// 	}
	//
	// 	// Cause
	// 	if cause != nil {
	// 		ie := ngapType.ErrorIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCause
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.ErrorIndicationIEsPresentCause
	// 		ie.Value.Cause = cause
	// 		errorIndicationIEs.List = append(errorIndicationIEs.List, ie)
	// 	}
	//
	// 	// Criticality Diagnostics
	// 	if criticalityDiagnostics != nil {
	// 		ie := ngapType.ErrorIndicationIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.ErrorIndicationIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = criticalityDiagnostics
	// 		errorIndicationIEs.List = append(errorIndicationIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildUERadioCapabilityInfoIndication() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildUERadioCapabilityCheckResponse(*context.TNGFUe, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeUERadioCapabilityCheck
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentUERadioCapabilityCheckResponse
	// 	successfulOutcome.Value.UERadioCapabilityCheckResponse = new(ngapType.UERadioCapabilityCheckResponse)
	//
	// 	uERadioCapabilityCheckResponse := successfulOutcome.Value.UERadioCapabilityCheckResponse
	// 	uERadioCapabilityCheckResponseIEs := &uERadioCapabilityCheckResponse.ProtocolIEs
	// 	// AMFUENGAPID
	// 	{
	// 		ie := ngapType.UERadioCapabilityCheckResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.UERadioCapabilityCheckResponseIEsPresentAMFUENGAPID
	// 		ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	//
	// 		aMFUENGAPID := ie.Value.AMFUENGAPID
	// 		aMFUENGAPID.Value = ue.AmfUeNgapId
	// 		uERadioCapabilityCheckResponseIEs.List = append(uERadioCapabilityCheckResponseIEs.List, ie)
	// 	}
	// 	// RANUENGAPID
	// 	{
	// 		ie := ngapType.UERadioCapabilityCheckResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.UERadioCapabilityCheckResponseIEsPresentRANUENGAPID
	// 		ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	//
	// 		rANUENGAPID := ie.Value.RANUENGAPID
	// 		rANUENGAPID.Value = ue.RanUeNgapId
	// 		uERadioCapabilityCheckResponseIEs.List = append(uERadioCapabilityCheckResponseIEs.List, ie)
	// 	}
	// 	// IMSVoiceSupportIndicator
	// 	{
	// 		ie := ngapType.UERadioCapabilityCheckResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDIMSVoiceSupportIndicator
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.UERadioCapabilityCheckResponseIEsPresentIMSVoiceSupportIndicator
	// 		ie.Value.IMSVoiceSupportIndicator = new(ngapType.IMSVoiceSupportIndicator)
	//
	// 		iMSVoiceSupportIndicator := ie.Value.IMSVoiceSupportIndicator
	// 		iMSVoiceSupportIndicator.Value = aper.Enumerated(ue.IMSVoiceSupported)
	// 		uERadioCapabilityCheckResponseIEs.List = append(uERadioCapabilityCheckResponseIEs.List, ie)
	// 	}
	// 	// CriticalityDiagnostics
	// 	if diagnostics != nil {
	// 		ie := ngapType.UERadioCapabilityCheckResponseIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.UERadioCapabilityCheckResponseIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = new(ngapType.CriticalityDiagnostics)
	//
	// 		criticalityDiagnostics := ie.Value.CriticalityDiagnostics
	// 		*criticalityDiagnostics = *diagnostics
	//
	// 		uERadioCapabilityCheckResponseIEs.List = append(uERadioCapabilityCheckResponseIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildAMFConfigurationUpdateAcknowledge(
	*ie.AMFTNLAssociationSetupList, *ie.TNLAssociationList, *ie.CriticalityDiagnostics,
) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	// 	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)
	//
	// 	successfulOutcome := pdu.SuccessfulOutcome
	// 	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeAMFConfigurationUpdate
	// 	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentAMFConfigurationUpdateAcknowledge
	// 	successfulOutcome.Value.AMFConfigurationUpdateAcknowledge = new(ngapType.AMFConfigurationUpdateAcknowledge)
	//
	// 	aMFConfigurationUpdateAcknowledge := successfulOutcome.Value.AMFConfigurationUpdateAcknowledge
	// 	aMFConfigurationUpdateAcknowledgeIEs := &aMFConfigurationUpdateAcknowledge.ProtocolIEs
	// 	// AMFTNLAssociationSetupList
	// 	if setupList != nil {
	// 		ie := ngapType.AMFConfigurationUpdateAcknowledgeIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFTNLAssociationSetupList
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateAcknowledgeIEsPresentAMFTNLAssociationSetupList
	// 		ie.Value.AMFTNLAssociationSetupList = new(ngapType.AMFTNLAssociationSetupList)
	//
	// 		aMFTNLAssociationSetupList := ie.Value.AMFTNLAssociationSetupList
	// 		*aMFTNLAssociationSetupList = *setupList
	//
	// 		aMFConfigurationUpdateAcknowledgeIEs.List = append(aMFConfigurationUpdateAcknowledgeIEs.List, ie)
	// 	}
	// 	// AMFTNLAssociationFailedToSetupList
	// 	if failList != nil {
	// 		ie := ngapType.AMFConfigurationUpdateAcknowledgeIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDAMFTNLAssociationFailedToSetupList
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateAcknowledgeIEsPresentAMFTNLAssociationFailedToSetupList
	// 		ie.Value.AMFTNLAssociationFailedToSetupList = new(ngapType.TNLAssociationList)
	//
	// 		aMFTNLAssociationFailedToSetupList := ie.Value.AMFTNLAssociationFailedToSetupList
	// 		*aMFTNLAssociationFailedToSetupList = *failList
	//
	// 		aMFConfigurationUpdateAcknowledgeIEs.List = append(aMFConfigurationUpdateAcknowledgeIEs.List, ie)
	// 	}
	// 	// CriticalityDiagnostics
	// 	if diagnostics != nil {
	// 		ie := ngapType.AMFConfigurationUpdateAcknowledgeIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateAcknowledgeIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = new(ngapType.CriticalityDiagnostics)
	//
	// 		criticalityDiagnostics := ie.Value.CriticalityDiagnostics
	// 		*criticalityDiagnostics = *diagnostics
	//
	// 		aMFConfigurationUpdateAcknowledgeIEs.List = append(aMFConfigurationUpdateAcknowledgeIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildAMFConfigurationUpdateFailure(ie.Cause, *ie.TimeToWait, *ie.CriticalityDiagnostics) ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	// 	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)
	//
	// 	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	// 	unsuccessfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeAMFConfigurationUpdate
	// 	unsuccessfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	unsuccessfulOutcome.Value.Present = ngapType.UnsuccessfulOutcomePresentAMFConfigurationUpdateFailure
	// 	unsuccessfulOutcome.Value.AMFConfigurationUpdateFailure = new(ngapType.AMFConfigurationUpdateFailure)
	//
	// 	aMFConfigurationUpdateFailure := unsuccessfulOutcome.Value.AMFConfigurationUpdateFailure
	// 	aMFConfigurationUpdateFailureIEs := &aMFConfigurationUpdateFailure.ProtocolIEs
	// 	// Cause
	// 	{
	// 		ie := ngapType.AMFConfigurationUpdateFailureIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCause
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateFailureIEsPresentCause
	// 		ie.Value.Cause = new(ngapType.Cause)
	//
	// 		cause := ie.Value.Cause
	// 		*cause = ngCause
	//
	// 		aMFConfigurationUpdateFailureIEs.List = append(aMFConfigurationUpdateFailureIEs.List, ie)
	// 	}
	// 	// TimeToWait
	// 	if time != nil {
	// 		ie := ngapType.AMFConfigurationUpdateFailureIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDTimeToWait
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateFailureIEsPresentTimeToWait
	// 		ie.Value.TimeToWait = new(ngapType.TimeToWait)
	//
	// 		timeToWait := ie.Value.TimeToWait
	// 		*timeToWait = *time
	//
	// 		aMFConfigurationUpdateFailureIEs.List = append(aMFConfigurationUpdateFailureIEs.List, ie)
	// 	}
	// 	// CriticalityDiagnostics
	// 	if diagnostics != nil {
	// 		ie := ngapType.AMFConfigurationUpdateFailureIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDCriticalityDiagnostics
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.AMFConfigurationUpdateFailureIEsPresentCriticalityDiagnostics
	// 		ie.Value.CriticalityDiagnostics = new(ngapType.CriticalityDiagnostics)
	//
	// 		criticalityDiagnostics := ie.Value.CriticalityDiagnostics
	// 		*criticalityDiagnostics = *diagnostics
	//
	// 		aMFConfigurationUpdateFailureIEs.List = append(aMFConfigurationUpdateFailureIEs.List, ie)
	// 	}
	//
	return nil, errBuilderNotImplemented
}

func BuildRANConfigurationUpdate() ([]byte, error) {
	// 	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	// 	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)
	//
	// 	initiatingMessage := pdu.InitiatingMessage
	// 	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeRANConfigurationUpdate
	// 	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	//
	// 	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentRANConfigurationUpdate
	// 	initiatingMessage.Value.RANConfigurationUpdate = new(ngapType.RANConfigurationUpdate)
	//
	// 	rANConfigurationUpdate := initiatingMessage.Value.RANConfigurationUpdate
	// 	rANConfigurationUpdateIEs := &rANConfigurationUpdate.ProtocolIEs
	//
	// 	tngfSelf := context.TNGFSelf()
	//
	// 	// RANNodeName
	// 	if tngfSelf.NFInfo.RanNodeName != "" {
	// 		ie := ngapType.RANConfigurationUpdateIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDRANNodeName
	// 		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 		ie.Value.Present = ngapType.RANConfigurationUpdateIEsPresentRANNodeName
	// 		ie.Value.RANNodeName = new(ngapType.RANNodeName)
	//
	// 		rANNodeName := ie.Value.RANNodeName
	// 		rANNodeName.Value = tngfSelf.NFInfo.RanNodeName
	//
	// 		rANConfigurationUpdateIEs.List = append(rANConfigurationUpdateIEs.List, ie)
	// 	}
	// 	// SupportedTAList
	// 	if len(tngfSelf.NFInfo.SupportedTAList) > 0 {
	// 		ie := ngapType.RANConfigurationUpdateIEs{}
	// 		ie.Id.Value = ngapType.ProtocolIEIDSupportedTAList
	// 		ie.Criticality.Value = ngapType.CriticalityPresentReject
	// 		ie.Value.Present = ngapType.RANConfigurationUpdateIEsPresentSupportedTAList
	// 		ie.Value.SupportedTAList = new(ngapType.SupportedTAList)
	//
	// 		supportedTAList := ie.Value.SupportedTAList
	//
	// 		for _, supportedTAItemLocal := range tngfSelf.NFInfo.SupportedTAList {
	// 			// SupportedTAItem in SupportedTAList
	// 			supportedTAItem := ngapType.SupportedTAItem{}
	// 			var err error
	// 			supportedTAItem.TAC.Value, err = hex.DecodeString(supportedTAItemLocal.TAC)
	// 			if err != nil {
	// 				logger.NgapLog.Errorf("DecodeString error: %+v", err)
	// 			}
	//
	// 			broadcastPLMNList := &supportedTAItem.BroadcastPLMNList
	//
	// 			for _, broadcastPLMNListLocal := range supportedTAItemLocal.BroadcastPLMNList {
	// 				// BroadcastPLMNItem in BroadcastPLMNList
	// 				broadcastPLMNItem := ngapType.BroadcastPLMNItem{}
	// 				broadcastPLMNItem.PLMNIdentity = util.PlmnIdToNgap(broadcastPLMNListLocal.PLMNID)
	//
	// 				sliceSupportList := &broadcastPLMNItem.TAISliceSupportList
	//
	// 				for _, sliceSupportItemLocal := range broadcastPLMNListLocal.TAISliceSupportList {
	// 					// SliceSupportItem in SliceSupportList
	// 					sliceSupportItem := ngapType.SliceSupportItem{}
	// 					sliceSupportItem.SNSSAI.SST.Value, err = hex.DecodeString(sliceSupportItemLocal.SNSSAI.SST)
	// 					if err != nil {
	// 						logger.NgapLog.Errorf("DecodeString error: %+v", err)
	// 					}
	//
	// 					if sliceSupportItemLocal.SNSSAI.SD != "" {
	// 						sliceSupportItem.SNSSAI.SD = new(ngapType.SD)
	// 						sliceSupportItem.SNSSAI.SD.Value, err = hex.DecodeString(sliceSupportItemLocal.SNSSAI.SD)
	// 						if err != nil {
	// 							logger.NgapLog.Errorf("DecodeString error: %+v", err)
	// 						}
	// 					}
	//
	// 					sliceSupportList.List = append(sliceSupportList.List, sliceSupportItem)
	// 				}
	//
	// 				broadcastPLMNList.List = append(broadcastPLMNList.List, broadcastPLMNItem)
	// 			}
	//
	// 			supportedTAList.List = append(supportedTAList.List, supportedTAItem)
	// 		}
	//
	// 		rANConfigurationUpdateIEs.List = append(rANConfigurationUpdateIEs.List, ie)
	// 	}
	// 	// DefaultPagingDRX
	// 	// {
	// 	// 	ie := ngapType.RANConfigurationUpdateIEs{}
	// 	// 	ie.Id.Value = ngapType.ProtocolIEIDDefaultPagingDRX
	// 	// 	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// 	// 	ie.Value.Present = ngapType.RANConfigurationUpdateIEsPresentDefaultPagingDRX
	// 	// 	ie.Value.DefaultPagingDRX = new(ngapType.PagingDRX)
	//
	// 	// 	defaultPagingDRX := ie.Value.DefaultPagingDRX
	//
	// 	// 	rANConfigurationUpdateIEs.List = append(rANConfigurationUpdateIEs.List, ie)
	// 	// }
	//
	return nil, errBuilderNotImplemented
}

func BuildUplinkRANConfigurationTransfer() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildUplinkRANStatusTransfer() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildLocationReportingFailureIndication() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildLocationReport() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildRRCInactiveTransitionReport() ([]byte, error) {
	return nil, errBuilderNotImplemented
}

func BuildPDUSessionResourceSetupResponseTransfer(pduSession *context.PDUSession) ([]byte, error) {
	address, err := transportLayerAddress(context.TNGFSelf().GTPBindAddress, "")
	if err != nil {
		return nil, err
	}
	teid := make([]byte, 4)
	binary.BigEndian.PutUint32(teid, pduSession.GTPConnection.IncomingTEID)

	qosFlowPerTNLInformation := &ie.QosFlowPerTNLInformation{
		UPTransportLayerInformation: &ie.UPTransportLayerInformation{
			Choice: &ie.GTPTunnel{
				TransportLayerAddress: address,
				GTPTEID:               &ie.GTPTEID{Value: teid},
			},
		},
		AssociatedQosFlowList: &ie.AssociatedQosFlowList{},
	}
	for _, qfi := range pduSession.QFIList {
		qosFlowPerTNLInformation.AssociatedQosFlowList.List = append(
			qosFlowPerTNLInformation.AssociatedQosFlowList.List,
			ie.AssociatedQosFlowItem{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: int64(qfi)}},
		)
	}

	return marshalTransfer(&ie.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: qosFlowPerTNLInformation,
	})
}

func BuildPDUSessionResourceSetupUnsuccessfulTransfer(
	cause ie.Cause, criticalityDiagnostics *ie.CriticalityDiagnostics,
) ([]byte, error) {
	return marshalTransfer(&ie.PDUSessionResourceSetupUnsuccessfulTransfer{
		Cause:                  &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	})
}

func BuildPDUSessionResourceModifyResponseTransfer(
	ulNGUUPTNLInformation *ie.UPTransportLayerInformation,
	dlNGUUPTNLInformation *ie.UPTransportLayerInformation,
	responseList *ie.QosFlowAddOrModifyResponseList,
	failedList *ie.QosFlowListWithCause,
) ([]byte, error) {
	return marshalTransfer(&ie.PDUSessionResourceModifyResponseTransfer{
		ULNGUUPTNLInformation:          ulNGUUPTNLInformation,
		DLNGUUPTNLInformation:          dlNGUUPTNLInformation,
		QosFlowAddOrModifyResponseList: responseList,
		QosFlowFailedToAddOrModifyList: failedList,
	})
}

func BuildPDUSessionResourceModifyUnsuccessfulTransfer(
	cause ie.Cause, criticalityDiagnostics *ie.CriticalityDiagnostics,
) ([]byte, error) {
	return marshalTransfer(&ie.PDUSessionResourceModifyUnsuccessfulTransfer{
		Cause:                  &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	})
}

func buildSupportedTAList(items []context.SupportedTAItem) (*ie.SupportedTAList, error) {
	list := &ie.SupportedTAList{}
	for _, item := range items {
		tac, err := hex.DecodeString(item.TAC)
		if err != nil {
			return nil, fmt.Errorf("decode TAC: %w", err)
		}
		supportedTAItem := ie.SupportedTAItem{
			TAC:               &ie.TAC{Value: tac},
			BroadcastPLMNList: &ie.BroadcastPLMNList{},
		}
		for _, broadcast := range item.BroadcastPLMNList {
			plmn := util.PlmnIdToNgap(broadcast.PLMNID)
			broadcastPLMNItem := ie.BroadcastPLMNItem{
				PLMNIdentity:        &plmn,
				TAISliceSupportList: &ie.SliceSupportList{},
			}
			for _, slice := range broadcast.TAISliceSupportList {
				sst, err := hex.DecodeString(slice.SNSSAI.SST)
				if err != nil {
					return nil, fmt.Errorf("decode S-NSSAI SST: %w", err)
				}
				snssai := &ie.SNSSAI{SST: &ie.SST{Value: sst}}
				if slice.SNSSAI.SD != "" {
					sd, err := hex.DecodeString(slice.SNSSAI.SD)
					if err != nil {
						return nil, fmt.Errorf("decode S-NSSAI SD: %w", err)
					}
					snssai.SD = &ie.SD{Value: sd}
				}
				broadcastPLMNItem.TAISliceSupportList.List = append(
					broadcastPLMNItem.TAISliceSupportList.List,
					ie.SliceSupportItem{SNSSAI: snssai},
				)
			}
			supportedTAItem.BroadcastPLMNList.List = append(
				supportedTAItem.BroadcastPLMNList.List, broadcastPLMNItem,
			)
		}
		list.List = append(list.List, supportedTAItem)
	}
	return list, nil
}

func buildUserLocationInformation(ue *context.TNGFUe) (*ie.UserLocationInformation, error) {
	address, err := transportLayerAddress(ue.IPAddrv4, ue.IPAddrv6)
	if err != nil {
		return nil, err
	}
	tnapID := make([]byte, 6)
	binary.BigEndian.PutUint16(tnapID[:2], uint16(ue.TNAPID>>32))
	binary.BigEndian.PutUint32(tnapID[2:], uint32(ue.TNAPID))
	return &ie.UserLocationInformation{
		Choice: &ie.ProtocolIESingleContainerUserLocationInformationExtIEs{
			UserLocationInformationExtIEs: ie.UserLocationInformationExtIEs{
				UserLocationInformationTNGF: &ie.UserLocationInformationTNGF{
					TNAPID:    &ie.TNAPID{Value: tnapID},
					IPAddress: address,
				},
			},
		},
	}, nil
}

func transportLayerAddress(ipv4, ipv6 string) (*ie.TransportLayerAddress, error) {
	address := &ie.TransportLayerAddress{}
	switch {
	case ipv4 != "" && ipv6 != "":
		v4 := net.ParseIP(ipv4).To4()
		v6 := net.ParseIP(ipv6).To16()
		if v4 == nil || v6 == nil {
			return nil, fmt.Errorf("invalid IPv4/IPv6 address: %q, %q", ipv4, ipv6)
		}
		address.Value = aper.BitString{Bytes: append(append([]byte{}, v4...), v6...), BitLength: 160}
	case ipv4 != "":
		v4 := net.ParseIP(ipv4).To4()
		if v4 == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %q", ipv4)
		}
		address.Value = aper.BitString{Bytes: v4, BitLength: 32}
	case ipv6 != "":
		v6 := net.ParseIP(ipv6).To16()
		if v6 == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %q", ipv6)
		}
		address.Value = aper.BitString{Bytes: v6, BitLength: 128}
	default:
		return nil, errors.New("at least one UE IP address is required")
	}
	return address, nil
}

func splitGUTI(guti string) (amfID, tmsi string, err error) {
	switch len(guti) {
	case 19:
		return guti[5:11], guti[11:], nil
	case 20:
		return guti[6:12], guti[12:], nil
	default:
		return "", "", fmt.Errorf("invalid GUTI length: %d", len(guti))
	}
}

func amfIDToNGAP(amfID string) (aper.BitString, aper.BitString, error) {
	if len(amfID) != 6 {
		return aper.BitString{}, aper.BitString{}, fmt.Errorf("invalid AMF ID length: %d", len(amfID))
	}
	setIDBytes, err := hex.DecodeString(amfID[2:5] + "0")
	if err != nil {
		return aper.BitString{}, aper.BitString{}, fmt.Errorf("decode AMF set ID: %w", err)
	}
	pointerBytes, err := hex.DecodeString(amfID[4:])
	if err != nil {
		return aper.BitString{}, aper.BitString{}, fmt.Errorf("decode AMF pointer: %w", err)
	}
	setIDBytes[1] &= 0xc0
	return aper.BitString{Bytes: setIDBytes, BitLength: 10},
		aper.BitString{Bytes: []byte{pointerBytes[0] << 2}, BitLength: 6}, nil
}

func marshalTransfer(value interface{ Write(*aper.PerBitData) error }) ([]byte, error) {
	data := aper.NewPerBitData(nil)
	if err := value.Write(data); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
