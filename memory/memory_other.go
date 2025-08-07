//go:build !ios

package memory

func InitForceFree() {}

// StopForceFree is a no-op on non-iOS platforms.
func StopForceFree() {}
