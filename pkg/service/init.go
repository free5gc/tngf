package service

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/tngf/internal/logger"
	ngap_service "github.com/free5gc/tngf/internal/ngap/service"
	nwtcp_service "github.com/free5gc/tngf/internal/nwtcp/service"
	nwtup_service "github.com/free5gc/tngf/internal/nwtup/service"
	"github.com/free5gc/tngf/internal/util"
	"github.com/free5gc/tngf/pkg/context"
	tngf_context "github.com/free5gc/tngf/pkg/context"
	"github.com/free5gc/tngf/pkg/factory"
	ike_service "github.com/free5gc/tngf/pkg/ike/service"
	"github.com/free5gc/tngf/pkg/ike/xfrm"
	radius_service "github.com/free5gc/tngf/pkg/radius/service"
)

type TngfApp struct {
	cfg     *factory.Config
	tngfCtx *tngf_context.TNGFContext
}

func NewApp(cfg *factory.Config) (*TngfApp, error) {
	if !util.InitTNGFContext() {
		logger.InitLog.Error("Initicating context failed")
		return nil, fmt.Errorf("Initicating context failed")
	}
	tngf := &TngfApp{
		cfg:     cfg,
		tngfCtx: tngf_context.TNGFSelf(),
	}
	tngf.SetLogEnable(cfg.GetLogEnable())
	tngf.SetLogLevel(cfg.GetLogLevel())
	tngf.SetReportCaller(cfg.GetLogReportCaller())

	return tngf, nil
}

func (a *TngfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to[%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *TngfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *TngfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller((reportCaller))
}

func (a *TngfApp) Start(tlsKeyLogPath string) {
	logger.InitLog.Infoln("Server started")

	if err := a.InitDefaultXfrmInterface(); err != nil {
		logger.InitLog.Errorf("Initicating XFRM interface for control plane failed: %+v", err)
		return
	}

	// Graceful Shutdown
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		<-signalChannel
		a.Terminate()
		// Waiting for negotiatioon with netlink for deleting interfaces
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	wg := sync.WaitGroup{}

	// NGAP
	if err := ngap_service.Run(); err != nil {
		logger.InitLog.Errorf("Start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Info("NGAP service running.")
	wg.Add(1)

	// Relay listeners
	// Control plane
	if err := nwtcp_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWt control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("NAS TCP server successfully started.")
	wg.Add(1)

	// User plane
	if err := nwtup_service.Run(); err != nil {
		logger.InitLog.Errorf("Listen NWt user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Info("Listening NWt user plane traffic")
	wg.Add(1)

	// IKE
	if err := ike_service.Run(); err != nil {
		logger.InitLog.Errorf("Start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Info("IKE service running.")
	wg.Add(1)

	// Radius
	if err := radius_service.Run(); err != nil {
		logger.InitLog.Errorf("Start Radius service failed: %+v", err)
		return
	}
	logger.InitLog.Info("Radius service running.")
	wg.Add(1)

	logger.InitLog.Info("TNGF running...")

	wg.Wait()
}

func (a *TngfApp) InitDefaultXfrmInterface() error {
	tngfContext := context.TNGFSelf()

	// Setup default IPsec interface for Control Plane
	var linkIPSec netlink.Link
	var err error
	tngfIPAddr := net.ParseIP(tngfContext.IPSecGatewayAddress).To4()
	tngfIPAddrAndSubnet := net.IPNet{IP: tngfIPAddr, Mask: tngfContext.Subnet.Mask}
	newXfrmiName := fmt.Sprintf("%s-default", tngfContext.XfrmIfaceName)

	if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, tngfContext.XfrmParentIfaceName,
		tngfContext.XfrmIfaceId, tngfIPAddrAndSubnet); err != nil {
		logger.InitLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
		return err
	}

	route := &netlink.Route{
		LinkIndex: linkIPSec.Attrs().Index,
		Dst:       tngfContext.Subnet,
	}

	if routeadd_err := netlink.RouteAdd(route); routeadd_err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", routeadd_err)
	}

	logger.InitLog.Infof("Setup XFRM interface %s ", newXfrmiName)

	tngfContext.XfrmIfaces.LoadOrStore(tngfContext.XfrmIfaceId, linkIPSec)
	tngfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (a *TngfApp) RemoveIPsecInterfaces() {
	tngfSelf := context.TNGFSelf()
	tngfSelf.XfrmIfaces.Range(
		func(key, value interface{}) bool {
			iface := value.(netlink.Link)
			if err := netlink.LinkDel(iface); err != nil {
				logger.InitLog.Errorf("Delete interface %s fail: %+v", iface.Attrs().Name, err)
			} else {
				logger.InitLog.Infof("Delete interface: %s", iface.Attrs().Name)
			}
			return true
		})
}

func (a *TngfApp) Terminate() {
	logger.InitLog.Info("Terminating TNGF...")
	logger.InitLog.Info("Deleting interfaces created by TNGF")
	a.RemoveIPsecInterfaces()
	logger.InitLog.Info("TNGF terminated")
}
