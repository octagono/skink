//go:build !windows
// +build !windows

package diskusage

import (
	"golang.org/x/sys/unix"
)

type DiskUsage struct {
	stat *unix.Statfs_t
}

// NewDiskUsage queries disk usage of volumePath, or nil on error.
func NewDiskUsage(volumePath string) *DiskUsage {
	stat := unix.Statfs_t{}
	err := unix.Statfs(volumePath, &stat)
	if err != nil {
		return nil
	}
	return &DiskUsage{&stat}
}

func (du *DiskUsage) Free() uint64 {
	return uint64(du.stat.Bfree) * uint64(du.stat.Bsize)
}

func (du *DiskUsage) Available() uint64 {
	return uint64(du.stat.Bavail) * uint64(du.stat.Bsize)
}

func (du *DiskUsage) Size() uint64 {
	return uint64(du.stat.Blocks) * uint64(du.stat.Bsize)
}

func (du *DiskUsage) Used() uint64 {
	return du.Size() - du.Free()
}

func (du *DiskUsage) Usage() float32 {
	return float32(du.Used()) / float32(du.Size())
}
