//go:build linux || darwin

package main

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// getListenConfig 返回一个启用了 SO_REUSEADDR 和 SO_REUSEPORT 的 net.ListenConfig
// 这个版本只在 Linux 和 Darwin 系统上编译。
func getListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// 启用地址复用
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					err = e
					return
				}
				// 启用端口复用
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
					err = e
					return
				}
			})
			return err
		},
	}
}
