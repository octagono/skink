package compress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"sync"

	log "github.com/schollz/logger"
)

// Method selects the compression algorithm.
type Method int

const (
	MethodDeflate Method = iota
	MethodGzip
	MethodNone
)

// currentMethod selects the compression method at build time.
// Never changed at runtime — effectively const after init.
const currentMethod = MethodDeflate

// gzipWriterPool reuses gzip.Writer instances across Compress calls.
// Each writer is Reset() before use to target a new output buffer.
var gzipWriterPool = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// gzipReaderPool reuses gzip.Reader instances across Decompress calls.
// Each reader is Reset() before use to source from a new input buffer.
var gzipReaderPool = sync.Pool{
	New: func() any { return new(gzip.Reader) },
}

// Compress src using the current compression method.
// Returns the original slice when MethodNone or on error.
func Compress(src []byte) []byte {
	if currentMethod == MethodNone {
		return src
	}
	if currentMethod == MethodGzip {
		var buf bytes.Buffer
		w := gzipWriterPool.Get().(*gzip.Writer)
		w.Reset(&buf)
		if _, err := w.Write(src); err != nil {
			log.Debugf("gzip compress: %v", err)
			w.Close()
			gzipWriterPool.Put(w)
			return src
		}
		w.Close()
		gzipWriterPool.Put(w)
		return buf.Bytes()
	}
	return CompressWithOption(src, flate.HuffmanOnly)
}

// CompressWithOption compresses src at the given flate level.
func CompressWithOption(src []byte, level int) []byte {
	if currentMethod == MethodNone {
		return src
	}
	var buf bytes.Buffer
	compress(src, &buf, level)
	return buf.Bytes()
}

// Decompress src using the current compression method.
// Returns the original slice when MethodNone or on error.
func Decompress(src []byte) []byte {
	if currentMethod == MethodNone {
		return src
	}
	if currentMethod == MethodGzip {
		r := gzipReaderPool.Get().(*gzip.Reader)
		if err := r.Reset(bytes.NewReader(src)); err != nil {
			log.Debugf("gzip decompress reset: %v", err)
			gzipReaderPool.Put(r)
			return src
		}
		defer gzipReaderPool.Put(r)
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			log.Debugf("gzip decompress copy: %v", err)
			r.Close()
			return buf.Bytes()
		}
		r.Close()
		return buf.Bytes()
	}
	compressedData := bytes.NewBuffer(src)
	decompressedData := new(bytes.Buffer)
	decompress(compressedData, decompressedData)
	return decompressedData.Bytes()
}

func compress(src []byte, dest io.Writer, level int) {
	w, err := flate.NewWriter(dest, level)
	if err != nil {
		log.Debugf("error creating flate writer: %v", err)
		return
	}
	if _, err := w.Write(src); err != nil {
		log.Debugf("error writing flate data: %v", err)
	}
	w.Close()
}

func decompress(src io.Reader, dest io.Writer) {
	r := flate.NewReader(src)
	defer r.Close()
	if _, err := io.Copy(dest, r); err != nil {
		log.Debugf("error copying flate data: %v", err)
	}
}
