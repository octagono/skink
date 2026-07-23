//go:build linux

package tunnel

import (
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// maxSpliceSize is the maximum bytes per splice(2) call.
// Linux kernel internally caps at 16 pages (64KB) anyway.
const maxSpliceSize = 64 << 10

// canSplice returns true if both connections are backed by TCP/Unix sockets
// (i.e., they expose raw file descriptors that splice(2) can operate on).
func canSplice(c net.Conn) bool {
	switch c.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	}
	return false
}

// rawFd extracts the underlying file descriptor from a connection.
// Returns -1 if the connection is not backed by an OS file.
func rawFd(c net.Conn) int {
	type fdGetter interface{ File() (*os.File, error) }
	switch v := c.(type) {
	case *net.TCPConn:
		rc, err := v.SyscallConn()
		if err != nil {
			return -1
		}
		fd := -1
		rc.Control(func(rawfd uintptr) {
			fd = int(rawfd)
		})
		return fd
	case *net.UnixConn:
		rc, err := v.SyscallConn()
		if err != nil {
			return -1
		}
		fd := -1
		rc.Control(func(rawfd uintptr) {
			fd = int(rawfd)
		})
		return fd
	}
	return -1
}

// spliceConnToConn zero-copies data from src to dst using splice(2) through
// an intermediate kernel pipe buffer. This avoids user-space data copies entirely.
// Requires both connections to be TCP or Unix sockets.
func spliceConnToConn(dst, src net.Conn) (int64, error) {
	dstFd := rawFd(dst)
	srcFd := rawFd(src)
	if dstFd < 0 || srcFd < 0 {
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		return io.CopyBuffer(dst, src, buf)
	}

	// Create a pipe for kernel-to-kernel data transfer
	var pipeFds [2]int
	if err := syscall.Pipe2(pipeFds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		return io.CopyBuffer(dst, src, buf)
	}
	defer syscall.Close(pipeFds[0])
	defer syscall.Close(pipeFds[1])

	var total int64
	for {
		// Splice from src socket → pipe
		n, err := spliceOnce(srcFd, pipeFds[1], maxSpliceSize)
		if n > 0 {
			// Splice from pipe → dst socket
			written, werr := drainPipe(pipeFds[0], dstFd, n)
			total += written
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

func spliceOnce(fdIn, fdOut, maxLen int) (int64, error) {
	flags := unix.SPLICE_F_MOVE | unix.SPLICE_F_NONBLOCK
	n, err := syscall.Splice(fdIn, nil, fdOut, nil, maxLen, flags)
	if err == syscall.EAGAIN {
		// Brief wait then retry once
		time.Sleep(100 * time.Microsecond)
		n, err = syscall.Splice(fdIn, nil, fdOut, nil, maxLen, flags)
	}
	if err == syscall.EAGAIN && n == 0 {
		// Treat persistent EAGAIN with zero bytes as EOF for non-blocking src
		return 0, io.EOF
	}
	return int64(n), err
}

func drainPipe(pipeFd, dstFd int, n int64) (int64, error) {
	var written int64
	for written < n {
		remaining := n - written
		if remaining > maxSpliceSize {
			remaining = maxSpliceSize
		}
		m, err := syscall.Splice(pipeFd, nil, dstFd, nil, int(remaining),
			unix.SPLICE_F_MOVE|unix.SPLICE_F_MORE)
		written += int64(m)
		if err != nil && err != syscall.EAGAIN {
			return written, err
		}
		if m == 0 {
			break
		}
	}
	return written, nil
}

// PipeConnZeroCopy uses splice(2) for bidirectional zero-copy piping on Linux.
// Falls back to pooled-buffer io.CopyBuffer for non-TCP connections.
func PipeConnZeroCopy(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	useSplice := canSplice(c1) && canSplice(c2)

	go func() {
		defer wg.Done()
		defer c1.Close()
		defer c2.Close()
		if useSplice {
			spliceConnToConn(c1, c2)
		} else {
			buf := getCopyBuf()
			defer putCopyBuf(buf)
			io.CopyBuffer(c1, c2, buf)
		}
	}()
	go func() {
		defer wg.Done()
		defer c1.Close()
		defer c2.Close()
		if useSplice {
			spliceConnToConn(c2, c1)
		} else {
			buf := getCopyBuf()
			defer putCopyBuf(buf)
			io.CopyBuffer(c2, c1, buf)
		}
	}()

	wg.Wait()
}
