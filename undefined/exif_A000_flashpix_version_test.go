package exifundefined

import (
	"bytes"
	"reflect"
	"testing"

	log "github.com/dsoprea/go-logging"
	exifcommon "github.com/krak3n/go-exif/v2/common"
)

func TestTagA000FlashpixVersion_String(t *testing.T) {
	versionPhrase := "some version"

	ut := TagA000FlashpixVersion{versionPhrase}

	s := ut.String()
	if s != versionPhrase {
		t.Fatalf("String not correct: [%s]", s)
	}
}

func TestCodecA000FlashpixVersion_Encode(t *testing.T) {
	versionPhrase := "some version"

	ut := TagA000FlashpixVersion{versionPhrase}

	codec := CodecA000FlashpixVersion{}

	encoded, unitCount, err := codec.Encode(ut, exifcommon.TestDefaultByteOrder)
	log.PanicIf(err)

	if bytes.Equal(encoded, []byte(versionPhrase)) != true {
		exifcommon.DumpBytesClause(encoded)

		t.Fatalf("Encoding not correct.")
	} else if unitCount != uint32(len(encoded)) {
		t.Fatalf("Unit-count not correct: (%d)", unitCount)
	}
}

func TestCodecA000FlashpixVersion_Decode(t *testing.T) {
	versionPhrase := "some version"

	expectedUt := TagA000FlashpixVersion{versionPhrase}

	encoded := []byte(versionPhrase)

	addressableBytes := encoded

	valueContext := exifcommon.NewValueContext(
		"",
		0,
		uint32(len(encoded)),
		0,
		nil,
		addressableBytes,
		exifcommon.TypeUndefined,
		exifcommon.TestDefaultByteOrder)

	codec := CodecA000FlashpixVersion{}

	decoded, err := codec.Decode(valueContext)
	log.PanicIf(err)

	if reflect.DeepEqual(decoded, expectedUt) != true {
		t.Fatalf("Decoded struct not correct.")
	}
}
