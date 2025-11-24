package ElGamal

import (
	"fmt"
)

// Pack large integer into a smaller one using base conversion
func PackInteger(largeInt int64, base int64) (int64, error) {
	var packed int64 = 0
	var multiplier int64 = 1

	for largeInt > 0 {
		digit := largeInt % base
		if digit >= 1000 {
			return 0, fmt.Errorf("digit too large to back")
		}
		packed += digit * multiplier
		multiplier *= 1000
		largeInt /= base
	}

	if packed > 999999 {
		return 0, fmt.Errorf("packed value exceeds the limit")
	}

	return packed, nil
}

// Unpack the smaller integer back to the original large integer
func unpackInteger(packed int64, base int64) int64 {
	var largeInt int64 = 0
	var multiplier int64 = 1

	for packed > 0 {
		digit := packed % 1000
		largeInt += digit * multiplier
		multiplier *= base
		packed /= 1000
	}

	return largeInt
}
