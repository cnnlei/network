package main

import (
	"context"
	"io"
	"net"
	"golang.org/x/time/rate"
)

// RateLimitedConn 是一个包装了 net.Conn 并实现了速率限制的结构体
type RateLimitedConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

// NewRateLimitedConn 创建一个新的速率限制连接
func NewRateLimitedConn(conn net.Conn, readLimiter, writeLimiter *rate.Limiter) *RateLimitedConn {
	return &RateLimitedConn{
		Conn:   conn,
		reader: &rateLimitedReader{r: conn, limiter: readLimiter},
		writer: &rateLimitedWriter{w: conn, limiter: writeLimiter},
	}
}

func (c *RateLimitedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *RateLimitedConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

// rateLimitedReader 包装了 io.Reader 以实现速率限制
type rateLimitedReader struct {
	r       io.Reader
	limiter *rate.Limiter
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	if r.limiter == nil {
		return r.r.Read(p)
	}
	n, err := r.r.Read(p)
	if err != nil {
		return n, err
	}
	if err := r.limiter.WaitN(context.Background(), n); err != nil {
		return n, err
	}
	return n, nil
}

// rateLimitedWriter 包装了 io.Writer 以实现速率限制
type rateLimitedWriter struct {
	w       io.Writer
	limiter *rate.Limiter
}

func (w *rateLimitedWriter) Write(p []byte) (int, error) {
	if w.limiter == nil {
		return w.w.Write(p)
	}
	n, err := w.w.Write(p)
	if err != nil {
		return n, err
	}
	if err := w.limiter.WaitN(context.Background(), n); err != nil {
		return n, err
	}
	return n, nil
}