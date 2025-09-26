//go:build windows

package main

import (
	"net"
)

// getListenConfig 在 Windows 上返回一个默认的 ListenConfig，
// 因为 Windows 不支持 SO_REUSEPORT。
func getListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
