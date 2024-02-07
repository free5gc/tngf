package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/asaskevich/govalidator"
	"github.com/urfave/cli"

	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/pkg/service"
	"github.com/free5gc/util/version"
)

var TNGF = &service.TNGF{}

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.AppLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	app := cli.NewApp()
	app.Name = "tngf"
	app.Usage = "Trusted Non-3GPP Gateway Function (TNGF)"
	app.Action = action
	app.Flags = TNGF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorf("TNGF Run Error: %v\n", err)
	}
}

func action(c *cli.Context) error {
	if err := initLogFile(c.String("log"), c.String("log5gc")); err != nil {
		logger.AppLog.Errorf("%+v", err)
		return err
	}

	if err := TNGF.Initialize(c); err != nil {
		switch errType := err.(type) {
		case govalidator.Errors:
			validErrs := err.(govalidator.Errors).Errors()
			for _, validErr := range validErrs {
				logger.CfgLog.Errorf("%+v", validErr)
			}
		default:
			logger.CfgLog.Errorf("%+v", errType)
		}
		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return fmt.Errorf("Failed to initialize !!")
	}

	logger.AppLog.Infoln(c.App.Name)
	logger.AppLog.Infoln("TNGF version: ", version.GetVersion())

	TNGF.Start()

	return nil
}

func initLogFile(logNfPath, log5gcPath string) error {
	if err := logger.LogFileHook(logNfPath, log5gcPath); err != nil {
		return err
	}
	return nil
}
