package hysteria2

import (
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/thebytearray/libHysteria2/memory"
	"go.uber.org/zap"
)

var (
	globalClient       client.Client
	isCoreRunning      bool
	logger             *zap.Logger
	coreMu             sync.Mutex
	coreActive         bool
	disableUpdateCheck bool = true
)

func init() {
	initHysteriaLogger()
	enableDefaultLogging()
}

func initHysteriaLogger() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		logger, _ = zap.NewProduction()
	}
	if logger != nil {
		logger.Info("Hysteria2 logger initialized")
	}
}

func StartTunnel(configJson string) error {
	coreMu.Lock()
	defer coreMu.Unlock()
	if coreActive {
		return errors.New("tunnel already running")
	}
	memory.InitForceFree()
	if logger != nil {
		logger.Info("Starting Hysteria2 tunnel")
	}
	var config clientConfig
	if err := json.Unmarshal([]byte(configJson), &config); err != nil {
		if logger != nil {
			logger.Error("Error while unmarshaling config", zap.Error(err))
		}
		memory.StopForceFree()
		return err
	}
	var err error
	globalClient, err = client.NewReconnectableClient(
		config.Config,
		func(c client.Client, info *client.HandshakeInfo, count int) {
			connectLog(info, count)
		},
		config.Lazy,
	)
	if err != nil {
		if logger != nil {
			logger.Error("Error while starting client", zap.Error(err))
		}
		memory.StopForceFree()
		return err
	}
	isCoreRunning = true
	coreActive = true
	var runner clientModeRunner
	if config.SOCKS5 != nil {
		runner.Add("SOCKS5 server", func() error { return clientSOCKS5(*config.SOCKS5, globalClient) })
	}
	if logger != nil {
		logger.Info("Hysteria2 tunnel started successfully")
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runnerChan := make(chan clientModeRunnerResult, 1)
	go func() {
		runnerChan <- runner.Run()
	}()

	go func() {
		for {
			select {
			case <-signalChan:
				if logger != nil {
					logger.Info("received signal, shutting down gracefully")
				}
				coreMu.Lock()
				isCoreRunning = false
				coreActive = false
				coreMu.Unlock()
				memory.StopForceFree()
				return
			case r := <-runnerChan:
				if r.OK {
					if logger != nil {
						logger.Info(r.Msg)
					}
					if logger != nil {
						logger.Warn("Runner completed unexpectedly, restarting...")
					}
					go func() {
						runnerChan <- runner.Run()
					}()
				} else {
					_ = globalClient.Close()
					if logger != nil {
						logger.Error(r.Msg, zap.Error(r.Err))
					}
					coreMu.Lock()
					isCoreRunning = false
					coreActive = false
					coreMu.Unlock()
					memory.StopForceFree()
					return
				}
			}
		}
	}()
	return nil
}

func StopTunnel() error {
	coreMu.Lock()
	defer coreMu.Unlock()
	if !coreActive {
		return errors.New("tunnel not running")
	}
	if logger != nil {
		logger.Info("Stopping Hysteria2 tunnel")
	}
	if globalClient != nil {
		_ = globalClient.Close()
		if logger != nil {
			logger.Info("Tunnel shutdown successful")
		}
	}
	isCoreRunning = false
	coreActive = false
	memory.StopForceFree()
	return nil
}

func GetCoreState() bool {
	coreMu.Lock()
	defer coreMu.Unlock()
	return coreActive
}

func TestConfig(configJson string) error {
	var config clientConfig
	if err := json.Unmarshal([]byte(configJson), &config); err != nil {
		return err
	}
	_, err := config.Config()
	return err
}

func connectLog(info *client.HandshakeInfo, count int) {
	if logger != nil {
		logger.Info("connected to server",
			zap.Bool("udpEnabled", info.UDPEnabled),
			zap.Uint64("tx", info.Tx),
			zap.Int("count", count))
	}
}

func SetLogger(customLogger *zap.Logger) {
	logger = customLogger
	if logger != nil {
		logger.Info("Custom logger set for Hysteria2")
	}
}

func DisableLogging() {
	logger = nil
}

func enableDefaultLogging() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		logger, _ = zap.NewProduction()
	}
	if logger != nil {
		logger.Info("Default logging re-enabled for Hysteria2")
	}
}
