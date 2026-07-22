//go:build !linux

package tunnel

import (
	"io"
	"net"
	"sync"
)

func canSplice(c net.Conn) bool { return false }

func sendFileToConn(dst net.Conn, src interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := getCopyBuf()
	defer putCopyBuf(buf)
	return io.CopyBuffer(dst, src, buf)
}

func PipeConnZeroCopy(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer c1.Close()
		defer c2.Close()
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		io.CopyBuffer(c1, c2, buf)
	}()
	go func() {
		defer wg.Done()
		defer c1.Close()
		defer c2.Close()
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		io.CopyBuffer(c2, c1, buf)
	}()

	wg.Wait()
}
