// Package r255 provides constants not provided by package ristretto255.
package r255

const (
	ElementSize = 32 // ElementSize is the length of an encoded ristretto255 element.
	ScalarSize  = 32 // ScalarSize is the length of an encoded ristretto255 scalar.

	// UniformBytestringSize is the length of a uniform bytestring which can be mapped to either a
	// ristretto255 element or scalar.
	UniformBytestringSize = 64
)
