package diskusage

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type DiskUsage struct {
	freeBytes  int64
	totalBytes int64
	availBytes int64
}

// NewDiskUsage queries disk usage of volumePath, or nil on error.
func NewDiskUsage(volumePath string) *DiskUsage {
	h := windows.MustLoadDLL("kernel32.dll")
	c := h.MustFindProc("GetDiskFreeSpaceExW")

	du := &DiskUsage{}

	c.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(volumePath))),
		uintptr(unsafe.Pointer(&du.freeBytes)),
		uintptr(unsafe.Pointer(&du.totalBytes)),
		uintptr(unsafe.Pointer(&du.availBytes)))

	return du
}

func (du *DiskUsage) Free() uint64 {
	return uint64(du.freeBytes)
}

func (du *DiskUsage) Available() uint64 {
	return uint64(du.availBytes)
}

func (du *DiskUsage) Size() uint64 {
	return uint64(du.totalBytes)
}

func (du *DiskUsage) Used() uint64 {
	return du.Size() - du.Free()
}

func (du *DiskUsage) Usage() float32 {
	return float32(du.Used()) / float32(du.Size())
}
