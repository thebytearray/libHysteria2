package libHysteria2

import (
	"github.com/thebytearray/libHysteria2/nodep"
)

func GetFreePorts(count int) ([]int, error) {
	return nodep.GetFreePorts(count)
}
func GetFreePort() (int, error) {
	ports, err := nodep.GetFreePorts(1)
	if err != nil {
		return 0, err
	}
	return ports[0], nil
}

func ConvBandwidth(bw interface{}) (uint64, error) {
	return nodep.ConvBandwidth(bw)
}

func StringToBps(s string) (uint64, error) {
	return nodep.StringToBps(s)
}
