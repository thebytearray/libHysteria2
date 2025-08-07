//go:build ios

package memory

import (
	"runtime/debug"
	"time"
	"sync"
)

const (
	interval = 1
	// 30M
	maxMemory = 30 * 1024 * 1024
)

var (
	forceFreeStopChan chan struct{}
	forceFreeOnce     sync.Once
)

func forceFree(interval time.Duration) {
	go func() {
		for {
			select {
			case <-time.After(interval):
				debug.FreeOSMemory()
			case <-forceFreeStopChan:
				return
			}
		}
	}()
}

func InitForceFree() {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(maxMemory)
	forceFreeOnce.Do(func() {
		forceFreeStopChan = make(chan struct{})
		duration := time.Duration(interval) * time.Second
		forceFree(duration)
	})
}

func StopForceFree() {
	if forceFreeStopChan != nil {
		close(forceFreeStopChan)
	}
}
