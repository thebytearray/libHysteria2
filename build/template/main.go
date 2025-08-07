package main

/*
#include <stdbool.h>
*/
import "C"
import (
	"github.com/thebytearray/libHysteria2/hysteria2"
)

func main() {}

//export CGoStartTunnel
func CGoStartTunnel(configJson *C.char) *C.char {
	goStr := C.GoString(configJson)
	err := hysteria2.StartTunnel(goStr)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export CGoStopTunnel
func CGoStopTunnel() *C.char {
	err := hysteria2.StopTunnel()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export CGoGetCoreState
func CGoGetCoreState() C.bool {
	if hysteria2.GetCoreState() {
		return C.bool(true)
	}
	return C.bool(false)
}

//export CGoTestConfig
func CGoTestConfig(configJson *C.char) *C.char {
	goStr := C.GoString(configJson)
	err := hysteria2.TestConfig(goStr)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}
