package compress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"

	log "github.com/schollz/logger"
)

type Method int

const (
	MethodDeflate Method = iota
	MethodGzip
	MethodNone
)

var currentMethod Method = MethodDeflate

func SetMethod(m Method) {
	currentMethod = m
}

func Compress(src []byte) []byte {
	if currentMethod == MethodNone {
		return src
	}
	if currentMethod == MethodGzip {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(src); err != nil {
			log.Debugf("gzip compress: %v", err)
			return src
		}
		w.Close()
		return buf.Bytes()
	}
	return CompressWithOption(src, flate.HuffmanOnly)
}

func CompressWithOption(src []byte, level int) []byte {
	if currentMethod == MethodNone {
		return src
	}
	compressedData := new(bytes.Buffer)
	compress(src, compressedData, level)
	return compressedData.Bytes()
}

func Decompress(src []byte) []byte {
	if currentMethod == MethodNone {
		return src
	}
	if currentMethod == MethodGzip {
		r, err := gzip.NewReader(bytes.NewReader(src))
		if err != nil {
			log.Debugf("gzip decompress: %v", err)
			return src
		}
		var buf bytes.Buffer
		io.Copy(&buf, r)
		r.Close()
		return buf.Bytes()
	}
	compressedData := bytes.NewBuffer(src)
	deCompressedData := new(bytes.Buffer)
	decompress(compressedData, deCompressedData)
	return deCompressedData.Bytes()
}

func compress(src []byte, dest io.Writer, level int) {
	compressor, err := flate.NewWriter(dest, level)
	if err != nil {
		log.Debugf("error level data: %v", err)
		return
	}
	if _, err := compressor.Write(src); err != nil {
		log.Debugf("error writing data: %v", err)
	}
	compressor.Close()
}

func decompress(src io.Reader, dest io.Writer) {
	decompressor := flate.NewReader(src)
	if _, err := io.Copy(dest, decompressor); err != nil {
		log.Debugf("error copying data: %v", err)
	}
	decompressor.Close()
}
