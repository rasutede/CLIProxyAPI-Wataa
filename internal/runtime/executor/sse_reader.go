package executor

import (
	"bufio"
	"bytes"
	"io"
)

// defaultSSEReaderSize is the buffer size for the underlying bufio.Reader.
// SSE lines are typically small (< 100KB). The reader uses a fixed-size
// internal buffer and ReadBytes returns independent slices, so memory
// does not grow unboundedly like bufio.Scanner.
const defaultSSEReaderSize = 64 * 1024 // 64KB

// SSELineReader reads SSE streams line by line using bufio.Reader.
// Unlike bufio.Scanner with a large max-token setting, the internal
// buffer stays at a fixed size regardless of line length, because
// ReadBytes allocates each returned line independently.
type SSELineReader struct {
	reader *bufio.Reader
}

// NewSSELineReader creates a line reader optimized for SSE streams.
func NewSSELineReader(r io.Reader) *SSELineReader {
	return &SSELineReader{
		reader: bufio.NewReaderSize(r, defaultSSEReaderSize),
	}
}

// ReadLine reads the next line from the stream, stripping the trailing newline.
// The returned byte slice is independently allocated and safe to retain.
// Empty lines (SSE event separators) are returned as zero-length non-nil slices.
// Returns io.EOF when the stream ends.
func (s *SSELineReader) ReadLine() ([]byte, error) {
	line, err := s.reader.ReadBytes('\n')
	if len(line) > 0 {
		// Strip trailing \n (and \r\n if present)
		line = bytes.TrimRight(line, "\r\n")
		// Return the line even if empty (SSE event separator)
		return line, err
	}
	if err != nil {
		return nil, err
	}
	// Shouldn't happen, but return empty line to be safe
	return []byte{}, nil
}
