// Package padding adds and removes padding for AES-CBC mode.
package padding

import "errors"

// RemovePadding removes padding from clear data.
func RemovePadding(bytesPadded []byte) ([]byte, error) {
	// last byte is padding byte
	paddingLen := int(bytesPadded[len(bytesPadded) - 1])
	if paddingLen > 16 {
		return nil, errors.New("Padding incorrect")
	}
	fileLen := len(bytesPadded) - paddingLen

	return bytesPadded[:fileLen], nil
}

// PadClearFile adds padding to clear file.
func PadClearFile(fileBytes []byte) (paddedFile []byte) {
	// pad with zeros, last byte is the size of padding
	paddingLen := 16 - len(fileBytes) % 16
	padding := make([]byte, paddingLen)
	padding[paddingLen - 1] = byte(paddingLen)
	paddedFile = append(fileBytes, padding...)

	return
}


