package main

import "io"

type xorReader struct {
	reader io.Reader
	key    string
	offset int64
}

func NewXorReader(reader io.Reader, key string, offset int64) *xorReader {
	return &xorReader{
		reader: reader,
		key:    key,
		offset: offset,
	}
}

func (r *xorReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)

	n2 := int64(n)
	keyLen := int64(len(r.key))
	for i := int64(0); i < n2; i++ {
		p[i] ^= r.key[(r.offset+i)%keyLen]
	}
	r.offset += n2

	return n, err
}

type xorWriter struct {
	writer io.Writer
	key    string
	offset int64
}

func NewXorWriter(writer io.Writer, key string) *xorWriter {
	return &xorWriter{
		writer: writer,
		key:    key,
	}
}

func (r *xorWriter) Write(p []byte) (n int, err error) {
	n2 := int64(len(p))

	keyLen := int64(len(r.key))
	for i := int64(0); i < n2; i++ {
		p[i] ^= r.key[(r.offset+i)%keyLen]
	}
	r.offset += n2

	return r.writer.Write(p)
}
