package libHysteria2

import (
	"github.com/thebytearray/libHysteria2/hysteria2"
)

func StartTunnel(configJson string) error {
	return hysteria2.StartTunnel(configJson)
}

func StopTunnel() error {
	return hysteria2.StopTunnel()
}

func GetCoreState() bool {
	return hysteria2.GetCoreState()
}

func TestConfig(configJson string) error {
	return hysteria2.TestConfig(configJson)
}
