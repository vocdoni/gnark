package ioutils

import "io"

type WriterCounter struct {
	W io.Writer
	N int64
}

func (w *WriterCounter) Write(p []byte) (n int, err error) {
	n, err = w.W.Write(p)
	w.N += int64(n)
	return
}

type ReaderCounter struct {
	R io.Reader
	N int64
}

func (cr *ReaderCounter) Read(p []byte) (int, error) {
	n, err := cr.R.Read(p)
	cr.N += int64(n)
	return n, err
}
