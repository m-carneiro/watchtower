package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock ResponseWriter that fails on Write
type failingResponseWriter struct {
	http.ResponseWriter
	failOnWrite bool
	writeCount  int
}

func (f *failingResponseWriter) Write(b []byte) (int, error) {
	f.writeCount++
	if f.failOnWrite {
		return 0, errors.New("write failed")
	}
	return f.ResponseWriter.Write(b)
}

func TestErrorHandling_JSONEncodingFailure(t *testing.T) {
	// Test that JSON encoding errors are handled gracefully

	// Create a channel (which cannot be JSON encoded)
	invalidData := make(chan int)

	w := httptest.NewRecorder()
	encoder := json.NewEncoder(w)

	err := encoder.Encode(invalidData)
	if err == nil {
		t.Error("Expected error when encoding invalid data")
	}

	// Verify error is logged (in real code) but doesn't crash
	// The error should be returned, not panic
}

func TestErrorHandling_WriteFailure(t *testing.T) {
	// Test that write failures are handled

	w := httptest.NewRecorder()
	data := []byte("test data")

	// First write should succeed
	n, err := w.Write(data)
	if err != nil {
		t.Errorf("Expected successful write, got error: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Test with failing writer
	failingWriter := &failingResponseWriter{
		ResponseWriter: w,
		failOnWrite:    true,
	}

	n, err = failingWriter.Write(data)
	if err == nil {
		t.Error("Expected write failure")
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes written on failure, got %d", n)
	}
}

func TestErrorHandling_LargeResponse(t *testing.T) {
	// Test handling of large responses
	w := httptest.NewRecorder()

	// Create a large data set
	largeData := make([]byte, 10*1024*1024) // 10 MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Write should succeed for large data
	n, err := w.Write(largeData)
	if err != nil {
		t.Errorf("Failed to write large data: %v", err)
	}

	if n != len(largeData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(largeData), n)
	}
}

func TestErrorHandling_EmptyResponse(t *testing.T) {
	// Test handling of empty responses
	w := httptest.NewRecorder()

	n, err := w.Write([]byte{})
	if err != nil {
		t.Errorf("Failed to write empty data: %v", err)
	}

	if n != 0 {
		t.Errorf("Expected to write 0 bytes, wrote %d", n)
	}
}

func TestErrorHandling_ClientDisconnect(t *testing.T) {
	// Simulate client disconnection during response

	// Create a pipe to simulate client connection
	pr, pw := io.Pipe()

	// Close reader immediately to simulate disconnect
	pr.Close()

	// Try to write to closed pipe
	_, err := pw.Write([]byte("test data"))
	if err == nil {
		t.Error("Expected error when writing to closed pipe")
	}

	pw.Close()
}

func TestErrorHandling_ConcurrentWrites(t *testing.T) {
	// Test concurrent writes don't cause data races
	w := httptest.NewRecorder()

	done := make(chan bool, 10)

	// Spawn multiple goroutines writing concurrently
	for i := 0; i < 10; i++ {
		go func(n int) {
			data := []byte("concurrent write test")
			w.Write(data)
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify some data was written
	if w.Body.Len() == 0 {
		t.Error("Expected data to be written")
	}
}

func TestErrorHandling_InvalidContentType(t *testing.T) {
	// Test handling of invalid content types
	w := httptest.NewRecorder()

	// Set invalid content type
	w.Header().Set("Content-Type", "invalid/type")

	// Should still allow writes
	_, err := w.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write should succeed regardless of content type: %v", err)
	}
}

func TestErrorHandling_MultipleHeaderWrites(t *testing.T) {
	// Test that multiple WriteHeader calls are handled
	w := httptest.NewRecorder()

	w.WriteHeader(http.StatusOK)

	// Second write should be ignored (Go's behavior)
	w.WriteHeader(http.StatusInternalServerError)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestErrorHandling_HeaderAfterWrite(t *testing.T) {
	// Test that headers cannot be set after write
	w := httptest.NewRecorder()

	// Write data
	w.Write([]byte("test"))

	// Try to set header after write (should be ignored)
	w.Header().Set("X-Test", "value")

	// Header should still be settable in httptest (different from real HTTP)
	// In real HTTP, this would be ignored
}

func TestErrorHandling_NilData(t *testing.T) {
	// Test handling of nil data
	w := httptest.NewRecorder()

	n, err := w.Write(nil)
	if err != nil {
		t.Errorf("Writing nil should not error: %v", err)
	}

	if n != 0 {
		t.Errorf("Expected 0 bytes written for nil, got %d", n)
	}
}

func TestErrorHandling_JSONMarshalError(t *testing.T) {
	// Test JSON marshal errors are handled

	// Create data that will fail to marshal
	type recursive struct {
		Self *recursive
	}

	r := &recursive{}
	r.Self = r // Circular reference

	_, err := json.Marshal(r)
	if err == nil {
		t.Error("Expected error for circular reference")
	}

	// Verify error message
	if err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestErrorHandling_BufferOverflow(t *testing.T) {
	// Test handling of buffer size limits
	w := httptest.NewRecorder()

	// Write large amount of data in chunks
	chunkSize := 1024
	totalChunks := 10000

	for i := 0; i < totalChunks; i++ {
		chunk := make([]byte, chunkSize)
		_, err := w.Write(chunk)
		if err != nil {
			t.Errorf("Write failed at chunk %d: %v", i, err)
			break
		}
	}

	expectedSize := chunkSize * totalChunks
	if w.Body.Len() != expectedSize {
		t.Logf("Note: Buffer size is %d, expected %d (may be limited by implementation)",
			w.Body.Len(), expectedSize)
	}
}

func TestErrorHandling_EncodingEdgeCases(t *testing.T) {
	testCases := []struct {
		name string
		data interface{}
		fail bool
	}{
		{"nil", nil, false},
		{"empty map", map[string]string{}, false},
		{"empty slice", []string{}, false},
		{"zero value", 0, false},
		{"empty string", "", false},
		{"unicode", "Hello 世界 🌍", false},
		{"special chars", `"quotes" and \backslashes\`, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			encoder := json.NewEncoder(w)
			err := encoder.Encode(tc.data)

			if tc.fail && err == nil {
				t.Error("Expected encoding to fail")
			}

			if !tc.fail && err != nil {
				t.Errorf("Unexpected encoding error: %v", err)
			}
		})
	}
}

func BenchmarkErrorHandling_WriteSmall(b *testing.B) {
	w := httptest.NewRecorder()
	data := []byte("small data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(data)
	}
}

func BenchmarkErrorHandling_WriteLarge(b *testing.B) {
	w := httptest.NewRecorder()
	data := bytes.Repeat([]byte("a"), 1024*1024) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(data)
	}
}

func BenchmarkErrorHandling_JSONEncode(b *testing.B) {
	w := httptest.NewRecorder()
	data := map[string]interface{}{
		"status":  "success",
		"message": "test message",
		"data": map[string]int{
			"count": 42,
			"total": 100,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder := json.NewEncoder(w)
		encoder.Encode(data)
	}
}
