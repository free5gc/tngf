package service

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"

	aperLogger "github.com/free5gc/aper/logger"
	"github.com/free5gc/tngf/internal/logger"
	ngap_service "github.com/free5gc/tngf/internal/ngap/service"
	nwtcp_service "github.com/free5gc/tngf/internal/nwtcp/service"
	nwtup_service "github.com/free5gc/tngf/internal/nwtup/service"
	"github.com/free5gc/tngf/internal/util"
	"github.com/free5gc/tngf/pkg/context"
	"github.com/free5gc/tngf/pkg/factory"
	ike_service "github.com/free5gc/tngf/pkg/ike/service"
	radius_service "github.com/free5gc/tngf/pkg/radius/service"
	"github.com/free5gc/tngf/pkg/ike/xfrm"
	ngapLogger "github.com/free5gc/ngap/logger"
)

type TNGF struct{}

type (
	// Commands information.
	Commands struct {
		config string
	}
)

var commands Commands

var cliCmd = []cli.Flag{
	cli.StringFlag{
		Name:  "config, c",
		Usage: "Load configuration from `FILE`",
	},
	cli.StringFlag{
		Name:  "log, l",
		Usage: "Output NF log to `FILE`",
	},
	cli.StringFlag{
		Name:  "log5gc, lc",
		Usage: "Output free5gc log to `FILE`",
	},
}

func (*TNGF) GetCliCmd() (flags []cli.Flag) {
	return cliCmd
}

func (tngf *TNGF) Initialize(c *cli.Context) error {
	commands = Commands{
		config: c.String("config"),
	}

	if commands.config != "" {
		if err := factory.InitConfigFactory(commands.config); err != nil {
			return err
		}
	} else {
		if err := factory.InitConfigFactory(util.TngfDefaultConfigPath); err != nil {
			return err
		}
	}

	tngf.SetLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	if _, err := factory.TngfConfig.Validate(); err != nil {
		return err
	}

	return nil
}

func (tngf *TNGF) SetLogLevel() {
	if factory.TngfConfig.Logger == nil {
		logger.InitLog.Warnln("TNGF config without log level setting!!!")
		return
	}

	if factory.TngfConfig.Logger.TNGF != nil {
		if factory.TngfConfig.Logger.TNGF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.TngfConfig.Logger.TNGF.DebugLevel); err != nil {
				logger.InitLog.Warnf("TNGF Log level [%s] is invalid, set to [info] level",
					factory.TngfConfig.Logger.TNGF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				logger.InitLog.Infof("TNGF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("TNGF Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.TngfConfig.Logger.TNGF.ReportCaller)
	}

	if factory.TngfConfig.Logger.NGAP != nil {
		if factory.TngfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.TngfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					factory.TngfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(logrus.InfoLevel)
		}
		ngapLogger.SetReportCaller(factory.TngfConfig.Logger.NGAP.ReportCaller)
	}

	if factory.TngfConfig.Logger.Aper != nil {
		if factory.TngfConfig.Logger.Aper.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.TngfConfig.Logger.Aper.DebugLevel); err != nil {
				aperLogger.AperLog.Warnf("Aper Log level [%s] is invalid, set to [info] level",
					factory.TngfConfig.Logger.Aper.DebugLevel)
				aperLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				aperLogger.SetLogLevel(level)
			}
		} else {
			aperLogger.AperLog.Warnln("Aper Log level not set. Default set to [info] level")
			aperLogger.SetLogLevel(logrus.InfoLevel)
		}
		aperLogger.SetReportCaller(factory.TngfConfig.Logger.Aper.ReportCaller)
	}
}

func (tngf *TNGF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range tngf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (tngf *TNGF) Start() {
	logger.InitLog.Infoln("Server started")

	if !util.InitTNGFContext() {
		logger.InitLog.Error("Initicating context failed")
		return
	}

	if err := tngf.InitDefaultXfrmInterface(); err != nil {
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
		tngf.Terminate()
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

func (tngf *TNGF) InitDefaultXfrmInterface() error {
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

	if err := netlink.RouteAdd(route); err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", err)
	}

	logger.InitLog.Infof("Setup XFRM interface %s ", newXfrmiName)

	tngfContext.XfrmIfaces.LoadOrStore(tngfContext.XfrmIfaceId, linkIPSec)
	tngfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (tngf *TNGF) RemoveIPsecInterfaces() {
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

func (tngf *TNGF) Terminate() {
	logger.InitLog.Info("Terminating TNGF...")
	logger.InitLog.Info("Deleting interfaces created by TNGF")
	tngf.RemoveIPsecInterfaces()
	logger.InitLog.Info("TNGF terminated")
}

func (tngf *TNGF) Exec(c *cli.Context) error {
	// TNGF.Initialize(cfgPath, c)

	logger.InitLog.Traceln("args:", c.String("tngfcfg"))
	args := tngf.FilterCli(c)
	logger.InitLog.Traceln("filter: ", args)
	command := exec.Command("./tngf", args...)

	wg := sync.WaitGroup{}
	wg.Add(3)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		if errCom := command.Start(); errCom != nil {
			logger.InitLog.Errorf("TNGF start error: %v", errCom)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
