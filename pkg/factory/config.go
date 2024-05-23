/*
 * TNGF Configuration Factory
 */

package factory

import (
	"fmt"
	"sync"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/tngf/internal/logger"
	"github.com/free5gc/tngf/pkg/context"
)

const (
	TngfExpectedConfigVersion = "1.0.3"
	TngfDefaultConfigPath     = "./config/tngfcfg.yaml"
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"optional"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if info := c.Info; info != nil {
		if result, err := info.validate(); err != nil {
			return result, err
		}
	}

	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"type(string),required"`
	Description string `yaml:"description,omitempty" valid:"type(string),optional"`
}

func (i *Info) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(i)
	return result, appendInvalid(err)
}

type Configuration struct {
	TNGFInfo         context.TNGFNFInfo         `yaml:"TNGFInformation" valid:"required"`
	AMFSCTPAddresses []context.AMFSCTPAddresses `yaml:"AMFSCTPAddresses" valid:"required"`

	TCPPort              uint16 `yaml:"NASTCPPort" valid:"port,required"`
	IKEBindAddr          string `yaml:"IKEBindAddress" valid:"host,required"`
	RadiusBindAddr       string `yaml:"RadiusBindAddress" valid:"host,required"`
	IPSecGatewayAddr     string `yaml:"IPSecTunnelAddress" valid:"host,required"`
	UEIPAddressRange     string `yaml:"UEIPAddressRange" valid:"cidr,required"`                // e.g. 10.0.1.0/24
	XfrmIfaceName        string `yaml:"XFRMInterfaceName" valid:"stringlength(1|10),optional"` // must != 0
	XfrmIfaceId          uint32 `yaml:"XFRMInterfaceID" valid:"numeric,optional"`              // must != 0
	GTPBindAddr          string `yaml:"GTPBindAddress" valid:"host,required"`
	FQDN                 string `yaml:"FQDN" valid:"url,required"` // e.g. tngf.free5gc.org
	PrivateKey           string `yaml:"PrivateKey" valid:"type(string),minstringlength(1),optional"`
	CertificateAuthority string `yaml:"CertificateAuthority" valid:"type(string),minstringlength(1),optional"`
	Certificate          string `yaml:"Certificate" valid:"type(string),minstringlength(1),optional"`
	RadiusSecret         string `yaml:"RadiusSecret" valid:"type(string),minstringlength(1),optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

func (c *Configuration) validate() (bool, error) {
	for _, amfSCTPAddress := range c.AMFSCTPAddresses {
		if result, err := amfSCTPAddress.Validate(); err != nil {
			return result, err
		}
	}

	govalidator.TagMap["cidr"] = govalidator.Validator(govalidator.IsCIDR)

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level: level,
		}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level:        "info",
			ReportCaller: reportCaller,
		}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}
