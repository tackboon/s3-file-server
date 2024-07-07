package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

func NewAESCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

type ctrReader struct {
	stream cipher.Stream
	reader io.Reader
	iv     []byte
}

func NewCTRReader(reader io.Reader, block cipher.Block, iv []byte, offset int64) (*ctrReader, error) {
	// calculate the initial counter value based on the IV and offset
	counter := binary.BigEndian.Uint64(iv[len(iv)-8:])
	counter += uint64(offset / aes.BlockSize)
	binary.BigEndian.PutUint64(iv[len(iv)-8:], counter)

	stream := cipher.NewCTR(block, iv)

	// advance the stream to the correct position within the block
	if offsetWithinBlock := offset % aes.BlockSize; offsetWithinBlock > 0 {
		dummy := make([]byte, offsetWithinBlock)
		stream.XORKeyStream(dummy, dummy)
	}

	return &ctrReader{stream: stream, reader: reader, iv: iv}, nil
}

func (r *ctrReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.stream.XORKeyStream(p[:n], p[:n])
	return n, err
}

type ctrWriter struct {
	stream cipher.Stream
	writer io.Writer
}

func NewCTRWriter(writer io.Writer, block cipher.Block) (*ctrWriter, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// set the last 4 bytes of the IV to zero for the counter
	counter := uint32(0)
	binary.BigEndian.PutUint32(iv[len(iv)-4:], counter)

	stream := cipher.NewCTR(block, iv)

	// write the iv to the writer so it can be used for decryption
	if _, err := writer.Write(iv); err != nil {
		return nil, err
	}

	return &ctrWriter{stream: stream, writer: writer}, nil
}

func (w *ctrWriter) Write(p []byte) (int, error) {
	cipher := make([]byte, len(p))
	w.stream.XORKeyStream(cipher, p)

	return w.writer.Write(cipher)
}
