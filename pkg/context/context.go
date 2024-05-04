package context

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"

	"github.com/free5gc/sctp"
	"github.com/sirupsen/logrus"
	gtpv1 "github.com/wmnsk/go-gtp/gtpv1"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/pkg/factory"
	"github.com/free5gc/util/idgenerator"
	// "fmt"
)

var contextLog *logrus.Entry

var tngfContext = TNGFContext{}

const RadiusDefaultSecret = "free5GC"

type TNGFContext struct {
	NFInfo           TNGFNFInfo
	AMFSCTPAddresses []*sctp.SCTPAddr

	// ID generator
	RANUENGAPIDGenerator *idgenerator.IDGenerator
	TEIDGenerator        *idgenerator.IDGenerator

	// Pools
	UePool                 sync.Map // map[int64]*TNGFUe, RanUeNgapID as key
	AMFPool                sync.Map // map[string]*TNGFAMF, SCTPAddr as key
	AMFReInitAvailableList sync.Map // map[string]bool, SCTPAddr as key
	IKESA                  sync.Map // map[uint64]*IKESecurityAssociation, SPI as key
	ChildSA                sync.Map // map[uint32]*ChildSecurityAssociation, inboundSPI as key
	GTPConnectionWithUPF   sync.Map // map[string]*gtpv1.UPlaneConn, UPF address as key
	AllocatedUEIPAddress   sync.Map // map[string]*TNGFUe, IPAddr as key
	AllocatedUETEID        sync.Map // map[uint32]*TNGFUe, TEID as key
	RadiusSessionPool      sync.Map // map[string]*RadiusSession, Calling Station ID as key

	// TNGF FQDN
	FQDN string

	// Security data
	CertificateAuthority []byte
	TNGFCertificate      []byte
	TNGFPrivateKey       *rsa.PrivateKey
	RadiusSecret         string

	// UEIPAddressRange
	Subnet *net.IPNet

	// XFRM interface
	XfrmIfaceId         uint32
	XfrmIfaces          sync.Map // map[uint32]*netlink.Link, XfrmIfaceId as key
	XfrmIfaceName       string
	XfrmParentIfaceName string

	// Every UE's first UP IPsec will use default XFRM interface, additoinal UP IPsec will offset its XFRM id
	XfrmIfaceIdOffsetForUP uint32

	// TNGF local address
	IKEBindAddress      string
	RadiusBindAddress   string
	IPSecGatewayAddress string
	GTPBindAddress      string
	TCPPort             uint16

	// TNGF NWt interface IPv4 packet connection
	NWtIPv4PacketConn *ipv4.PacketConn
}

func init() {
	// init log
	contextLog = logger.ContextLog

	// init ID generator
	tngfContext.RANUENGAPIDGenerator = idgenerator.NewGenerator(0, math.MaxInt64)
	tngfContext.TEIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)
}

func InitTNGFContext() bool {
	var ok bool
	contextLog = logger.ContextLog

	if factory.TngfConfig.Configuration == nil {
		contextLog.Error("No TNGF configuration found")
		return false
	}

	tngfContext := TNGFSelf()

	// TNGF NF information
	tngfContext.NFInfo = factory.TngfConfig.Configuration.TNGFInfo
	if ok = util.formatSupportedTAList(&tngfContext.NFInfo); !ok {
		return false
	}

	// AMF SCTP addresses
	if len(factory.TngfConfig.Configuration.AMFSCTPAddresses) == 0 {
		contextLog.Error("No AMF specified")
		return false
	} else {
		for _, amfAddress := range factory.TngfConfig.Configuration.AMFSCTPAddresses {
			amfSCTPAddr := new(sctp.SCTPAddr)
			// IP addresses
			for _, ipAddrStr := range amfAddress.IPAddresses {
				if ipAddr, err := net.ResolveIPAddr("ip", ipAddrStr); err != nil {
					contextLog.Errorf("Resolve AMF IP address failed: %+v", err)
					return false
				} else {
					amfSCTPAddr.IPAddrs = append(amfSCTPAddr.IPAddrs, *ipAddr)
				}
			}
			// Port
			if amfAddress.Port == 0 {
				amfSCTPAddr.Port = 38412
			} else {
				amfSCTPAddr.Port = amfAddress.Port
			}
			// Append to context
			tngfContext.AMFSCTPAddresses = append(tngfContext.AMFSCTPAddresses, amfSCTPAddr)
		}
	}

	// IKE bind address
	if factory.TngfConfig.Configuration.IKEBindAddr == "" {
		contextLog.Error("IKE bind address is empty")
		return false
	} else {
		tngfContext.IKEBindAddress = factory.TngfConfig.Configuration.IKEBindAddr
	}

	// Radius bind address
	if factory.TngfConfig.Configuration.RadiusBindAddr == "" {
		contextLog.Error("IKE bind address is empty")
		return false
	} else {
		tngfContext.RadiusBindAddress = factory.TngfConfig.Configuration.RadiusBindAddr
	}

	// IPSec gateway address
	if factory.TngfConfig.Configuration.IPSecGatewayAddr == "" {
		contextLog.Error("IPSec interface address is empty")
		return false
	} else {
		tngfContext.IPSecGatewayAddress = factory.TngfConfig.Configuration.IPSecGatewayAddr
	}

	// GTP bind address
	if factory.TngfConfig.Configuration.GTPBindAddr == "" {
		contextLog.Error("GTP bind address is empty")
		return false
	} else {
		tngfContext.GTPBindAddress = factory.TngfConfig.Configuration.GTPBindAddr
	}

	// TCP port
	if factory.TngfConfig.Configuration.TCPPort == 0 {
		contextLog.Error("TCP port is not defined")
		return false
	} else {
		tngfContext.TCPPort = factory.TngfConfig.Configuration.TCPPort
	}

	// FQDN
	if factory.TngfConfig.Configuration.FQDN == "" {
		contextLog.Error("FQDN is empty")
		return false
	} else {
		tngfContext.FQDN = factory.TngfConfig.Configuration.FQDN
	}

	// Private key
	{
		var keyPath string

		if factory.TngfConfig.Configuration.PrivateKey == "" {
			contextLog.Warn("No private key file path specified, load default key file...")
			keyPath = TngfDefaultKeyPath
		} else {
			keyPath = factory.TngfConfig.Configuration.PrivateKey
		}

		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read private key data from file: %+v", err)
			return false
		}
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			contextLog.Warnf("Parse PKCS8 private key failed: %+v", err)
			contextLog.Info("Parse using PKCS1...")

			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				contextLog.Errorf("Parse PKCS1 pricate key failed: %+v", err)
				return false
			}
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			contextLog.Error("Private key is not an rsa private key")
			return false
		}

		tngfContext.TNGFPrivateKey = rsaKey
	}

	// Certificate authority
	{
		var keyPath string

		if factory.TngfConfig.Configuration.CertificateAuthority == "" {
			contextLog.Warn("No certificate authority file path specified, load default CA certificate...")
			keyPath = TngfDefaultPemPath
		} else {
			keyPath = factory.TngfConfig.Configuration.CertificateAuthority
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate authority data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}
		// Parse DER-encoded x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			contextLog.Errorf("Parse certificate authority failed: %+v", err)
			return false
		}
		// Get sha1 hash of subject public key info
		sha1Hash := sha1.New()
		if _, err := sha1Hash.Write(cert.RawSubjectPublicKeyInfo); err != nil {
			contextLog.Errorf("Hash function writing failed: %+v", err)
			return false
		}

		tngfContext.CertificateAuthority = sha1Hash.Sum(nil)
	}

	// Certificate
	{
		var keyPath string

		if factory.TngfConfig.Configuration.Certificate == "" {
			contextLog.Warn("No certificate file path specified, load default certificate...")
			keyPath = TngfDefaultPemPath
		} else {
			keyPath = factory.TngfConfig.Configuration.Certificate
		}

		// Read .pem
		content, err := ioutil.ReadFile(keyPath)
		if err != nil {
			contextLog.Errorf("Cannot read certificate data from file: %+v", err)
			return false
		}
		// Decode pem
		block, _ := pem.Decode(content)
		if block == nil {
			contextLog.Error("Parse pem failed")
			return false
		}

		tngfContext.TNGFCertificate = block.Bytes
	}

	// Radius Secret
	{
		if factory.TngfConfig.Configuration.RadiusSecret == "" {
			contextLog.Warn("No RADIUS secret specified, load default secret...")
			tngfContext.RadiusSecret = RadiusDefaultSecret
		} else {
			tngfContext.RadiusSecret = factory.TngfConfig.Configuration.RadiusSecret
		}
	}

	// UE IP address range
	if factory.TngfConfig.Configuration.UEIPAddressRange == "" {
		contextLog.Error("UE IP address range is empty")
		return false
	} else {
		_, ueIPRange, err := net.ParseCIDR(factory.TngfConfig.Configuration.UEIPAddressRange)
		if err != nil {
			contextLog.Errorf("Parse CIDR failed: %+v", err)
			return false
		}
		tngfContext.Subnet = ueIPRange
	}

	// XFRM related
	ikeBindIfaceName, err := GetInterfaceName(factory.TngfConfig.Configuration.IKEBindAddr)
	if err != nil {
		contextLog.Error(err)
		return false
	} else {
		tngfContext.XfrmParentIfaceName = ikeBindIfaceName
	}

	if factory.TngfConfig.Configuration.XfrmIfaceName == "" {
		contextLog.Error("XFRM interface Name is empty, set to default \"ipsec\"")
		tngfContext.XfrmIfaceName = "ipsec"
	} else {
		tngfContext.XfrmIfaceName = factory.TngfConfig.Configuration.XfrmIfaceName
	}

	if factory.TngfConfig.Configuration.XfrmIfaceId == 0 {
		contextLog.Warn("XFRM interface id is not defined, set to default value 7")
		tngfContext.XfrmIfaceId = 7
	} else {
		tngfContext.XfrmIfaceId = factory.TngfConfig.Configuration.XfrmIfaceId
	}

	return true
}

// Create new TNGF context
func TNGFSelf() *TNGFContext {
	return &tngfContext
}

func (context *TNGFContext) NewRadiusSession(callingStationID string) *RadiusSession {
	radiusSession := new(RadiusSession)
	radiusSession.CallingStationID = callingStationID
	context.RadiusSessionPool.Store(callingStationID, radiusSession)
	return radiusSession
}

func (context *TNGFContext) DeleteRadiusSession(ranUeNgapId string) {
	context.RadiusSessionPool.Delete(ranUeNgapId)
}

func (context *TNGFContext) RadiusSessionPoolLoad(ranUeNgapId string) (*RadiusSession, bool) {
	ue, ok := context.RadiusSessionPool.Load(ranUeNgapId)
	if ok {
		return ue.(*RadiusSession), ok
	} else {
		return nil, ok
	}
}
func (context *TNGFContext) NewTngfUe() *TNGFUe {
	ranUeNgapId, err := context.RANUENGAPIDGenerator.Allocate()
	if err != nil {
		contextLog.Errorf("New TNGF UE failed: %+v", err)
		return nil
	}
	tngfUe := new(TNGFUe)
	tngfUe.init(ranUeNgapId)
	context.UePool.Store(ranUeNgapId, tngfUe)
	return tngfUe
}

func (context *TNGFContext) DeleteTngfUe(ranUeNgapId int64) {
	context.UePool.Delete(ranUeNgapId)
}

func (context *TNGFContext) UePoolLoad(ranUeNgapId int64) (*TNGFUe, bool) {
	ue, ok := context.UePool.Load(ranUeNgapId)
	if ok {
		return ue.(*TNGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) NewTngfAmf(sctpAddr string, conn *sctp.SCTPConn) *TNGFAMF {
	amf := new(TNGFAMF)
	amf.init(sctpAddr, conn)
	if item, loaded := context.AMFPool.LoadOrStore(sctpAddr, amf); loaded {
		contextLog.Warn("[Context] NewTngfAmf(): AMF entry already exists.")
		return item.(*TNGFAMF)
	} else {
		return amf
	}
}

func (context *TNGFContext) DeleteTngfAmf(sctpAddr string) {
	context.AMFPool.Delete(sctpAddr)
}

func (context *TNGFContext) AMFPoolLoad(sctpAddr string) (*TNGFAMF, bool) {
	amf, ok := context.AMFPool.Load(sctpAddr)
	if ok {
		return amf.(*TNGFAMF), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) DeleteAMFReInitAvailableFlag(sctpAddr string) {
	context.AMFReInitAvailableList.Delete(sctpAddr)
}

func (context *TNGFContext) AMFReInitAvailableListLoad(sctpAddr string) (bool, bool) {
	flag, ok := context.AMFReInitAvailableList.Load(sctpAddr)
	if ok {
		return flag.(bool), ok
	} else {
		return true, ok
	}
}

func (context *TNGFContext) AMFReInitAvailableListStore(sctpAddr string, flag bool) {
	context.AMFReInitAvailableList.Store(sctpAddr, flag)
}

func (context *TNGFContext) NewIKESecurityAssociation() *IKESecurityAssociation {
	ikeSecurityAssociation := new(IKESecurityAssociation)

	var maxSPI *big.Int = new(big.Int).SetUint64(math.MaxUint64)
	var localSPIuint64 uint64

	for {
		localSPI, err := rand.Int(rand.Reader, maxSPI)
		if err != nil {
			contextLog.Error("[Context] Error occurs when generate new IKE SPI")
			return nil
		}
		localSPIuint64 = localSPI.Uint64()
		if _, duplicate := context.IKESA.LoadOrStore(localSPIuint64, ikeSecurityAssociation); !duplicate {
			break
		}
	}

	ikeSecurityAssociation.LocalSPI = localSPIuint64

	return ikeSecurityAssociation
}

func (context *TNGFContext) DeleteIKESecurityAssociation(spi uint64) {
	context.IKESA.Delete(spi)
}

func (context *TNGFContext) UELoadbyIDi(idi []byte) *TNGFUe {
	var ue *TNGFUe
	context.UePool.Range(func(_, thisUE interface{}) bool {
		strIdi := hex.EncodeToString(idi)
		strSuci := hex.EncodeToString(thisUE.(*TNGFUe).UEIdentity.Buffer)
		contextLog.Debugln("Idi", strIdi)
		contextLog.Debugln("SUCI", strSuci)
		if strIdi == strSuci {
			ue = thisUE.(*TNGFUe)
			return false
		}
		return true
	})
	return ue
}

func (context *TNGFContext) IKESALoad(spi uint64) (*IKESecurityAssociation, bool) {
	securityAssociation, ok := context.IKESA.Load(spi)
	if ok {
		return securityAssociation.(*IKESecurityAssociation), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) DeleteGTPConnection(upfAddr string) {
	context.GTPConnectionWithUPF.Delete(upfAddr)
}

func (context *TNGFContext) GTPConnectionWithUPFLoad(upfAddr string) (*gtpv1.UPlaneConn, bool) {
	conn, ok := context.GTPConnectionWithUPF.Load(upfAddr)
	if ok {
		return conn.(*gtpv1.UPlaneConn), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) GTPConnectionWithUPFStore(upfAddr string, conn *gtpv1.UPlaneConn) {
	context.GTPConnectionWithUPF.Store(upfAddr, conn)
}

func (context *TNGFContext) NewInternalUEIPAddr(ue *TNGFUe) net.IP {
	var ueIPAddr net.IP

	// TODO: Check number of allocated IP to detect running out of IPs
	for {
		ueIPAddr = generateRandomIPinRange(context.Subnet)
		if ueIPAddr != nil {
			if ueIPAddr.String() == context.IPSecGatewayAddress {
				continue
			}
			if _, ok := context.AllocatedUEIPAddress.LoadOrStore(ueIPAddr.String(), ue); !ok {
				break
			}
		}
	}

	return ueIPAddr
}

func (context *TNGFContext) DeleteInternalUEIPAddr(ipAddr string) {
	context.AllocatedUEIPAddress.Delete(ipAddr)
}

func (context *TNGFContext) AllocatedUEIPAddressLoad(ipAddr string) (*TNGFUe, bool) {
	ue, ok := context.AllocatedUEIPAddress.Load(ipAddr)
	if ok {
		return ue.(*TNGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) NewTEID(ue *TNGFUe) uint32 {
	teid64, err := context.TEIDGenerator.Allocate()
	if err != nil {
		contextLog.Errorf("New TEID failed: %+v", err)
		return 0
	}
	teid32 := uint32(teid64)

	context.AllocatedUETEID.Store(teid32, ue)

	return teid32
}

func (context *TNGFContext) DeleteTEID(teid uint32) {
	context.AllocatedUETEID.Delete(teid)
}

func (context *TNGFContext) AllocatedUETEIDLoad(teid uint32) (*TNGFUe, bool) {
	ue, ok := context.AllocatedUETEID.Load(teid)
	if ok {
		return ue.(*TNGFUe), ok
	} else {
		return nil, ok
	}
}

func (context *TNGFContext) AMFSelection(ueSpecifiedGUAMI *ngapType.GUAMI,
	ueSpecifiedPLMNId *ngapType.PLMNIdentity) *TNGFAMF {
	var availableAMF *TNGFAMF
	context.AMFPool.Range(func(key, value interface{}) bool {
		amf := value.(*TNGFAMF)
		if amf.FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI) {
			availableAMF = amf
			return false
		} else {
			// Fail to find through GUAMI served by UE.
			// Try again using SelectedPLMNId
			if amf.FindAvalibleAMFByCompareSelectedPLMNId(ueSpecifiedPLMNId) {
				availableAMF = amf
				return false
			} else {
				return true
			}
		}
	})
	return availableAMF
}

func generateRandomIPinRange(subnet *net.IPNet) net.IP {
	ipAddr := make([]byte, 4)
	randomNumber := make([]byte, 4)

	_, err := rand.Read(randomNumber)
	if err != nil {
		contextLog.Errorf("Generate random number for IP address failed: %+v", err)
		return nil
	}

	// TODO: elimenate network name, gateway, and broadcast
	for i := 0; i < 4; i++ {
		alter := randomNumber[i] & (subnet.Mask[i] ^ 255)
		ipAddr[i] = subnet.IP[i] + alter
	}

	return net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}

func GetInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "nil", err
	}

	for _, inter := range interfaces {
		addrs, err := inter.Addrs()
		if err != nil {
			return "nil", err
		}
		for _, addr := range addrs {
			if IPAddress == addr.String()[0:strings.Index(addr.String(), "/")] {
				return inter.Name, nil
			}
		}
	}
	return "", fmt.Errorf("Cannot find interface name")
}
