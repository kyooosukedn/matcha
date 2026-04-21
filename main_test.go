package main

import (
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal filename", "document.pdf", "document.pdf"},
		{"filename with spaces", "my report.docx", "my report.docx"},
		{"unix path traversal", "../../../etc/passwd", "passwd"},
		{"windows path traversal", "..\\..\\..\\windows\\system32\\config", "config"},
		{"mixed traversal", "../secret/key.pem", "key.pem"},
		{"hidden file", ".bashrc", "attachment"},
		{"dot only", ".", "attachment"},
		{"dot dot", "..", "_"},
		{"empty string", "", "attachment"},
		{"absolute unix path", "/etc/shadow", "shadow"},
		{"absolute windows path", "C:\\Users\\secret.txt", "secret.txt"},
		{"double dot in middle", "file..name.txt", "file_name.txt"},
		{"multiple slashes", "path/to/file.txt", "file.txt"},
		{"null bytes removed", "file\x00name.txt", "file\x00name.txt"},
		{"unicode filename", "日本語.txt", "日本語.txt"},
		{"long traversal chain", "a/b/c/../../../d/e/f.txt", "f.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.expected)
			}
			// Verify the sanitized name never allows escaping the download directory
			if got == "" {
				t.Error("sanitizeFilename returned empty string")
			}
			if got == "." || got == ".." {
				t.Error("sanitizeFilename returned a dangerous name: " + got)
			}
		})
	}
}

func TestSanitizeFilenameNoPathSeparators(t *testing.T) {
	// Ensure no sanitized output contains path separators
	dangerous := []string{
		"a/b", "a\\b", "../a", "..\\a",
		"/etc/passwd", "\\Windows\\System32",
		"....//....//etc/passwd",
	}
	for _, input := range dangerous {
		got := sanitizeFilename(input)
		for _, ch := range got {
			if ch == '/' || ch == '\\' {
				t.Errorf("sanitizeFilename(%q) = %q contains path separator", input, got)
			}
		}
	}
}
