package exif

import (
	"bytes"
	"fmt"
	"strings"

	"crypto/sha1"
	"encoding/binary"

	"github.com/dsoprea/go-logging"
)

const (
	UnparseableUnknownTagValuePlaceholder = "!UNKNOWN"
)

// TODO(dustin): Rename "unknown" in symbol names to "undefined" in the next release.
//
// See https://github.com/dsoprea/go-exif/issues/27 .

const (
	TagUnknownType_9298_UserComment_Encoding_ASCII     = iota
	TagUnknownType_9298_UserComment_Encoding_JIS       = iota
	TagUnknownType_9298_UserComment_Encoding_UNICODE   = iota
	TagUnknownType_9298_UserComment_Encoding_UNDEFINED = iota
)

const (
	TagUnknownType_9101_ComponentsConfiguration_Channel_Y  = 0x1
	TagUnknownType_9101_ComponentsConfiguration_Channel_Cb = 0x2
	TagUnknownType_9101_ComponentsConfiguration_Channel_Cr = 0x3
	TagUnknownType_9101_ComponentsConfiguration_Channel_R  = 0x4
	TagUnknownType_9101_ComponentsConfiguration_Channel_G  = 0x5
	TagUnknownType_9101_ComponentsConfiguration_Channel_B  = 0x6
)

const (
	TagUnknownType_9101_ComponentsConfiguration_OTHER = iota
	TagUnknownType_9101_ComponentsConfiguration_RGB   = iota
	TagUnknownType_9101_ComponentsConfiguration_YCBCR = iota
)

var (
	TagUnknownType_9298_UserComment_Encoding_Names = map[int]string{
		TagUnknownType_9298_UserComment_Encoding_ASCII:     "ASCII",
		TagUnknownType_9298_UserComment_Encoding_JIS:       "JIS",
		TagUnknownType_9298_UserComment_Encoding_UNICODE:   "UNICODE",
		TagUnknownType_9298_UserComment_Encoding_UNDEFINED: "UNDEFINED",
	}

	TagUnknownType_9298_UserComment_Encodings = map[int][]byte{
		TagUnknownType_9298_UserComment_Encoding_ASCII:     []byte{'A', 'S', 'C', 'I', 'I', 0, 0, 0},
		TagUnknownType_9298_UserComment_Encoding_JIS:       []byte{'J', 'I', 'S', 0, 0, 0, 0, 0},
		TagUnknownType_9298_UserComment_Encoding_UNICODE:   []byte{'U', 'n', 'i', 'c', 'o', 'd', 'e', 0},
		TagUnknownType_9298_UserComment_Encoding_UNDEFINED: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	TagUnknownType_9101_ComponentsConfiguration_Names = map[int]string{
		TagUnknownType_9101_ComponentsConfiguration_OTHER: "OTHER",
		TagUnknownType_9101_ComponentsConfiguration_RGB:   "RGB",
		TagUnknownType_9101_ComponentsConfiguration_YCBCR: "YCBCR",
	}

	TagUnknownType_9101_ComponentsConfiguration_Configurations = map[int][]byte{
		TagUnknownType_9101_ComponentsConfiguration_RGB: []byte{
			TagUnknownType_9101_ComponentsConfiguration_Channel_R,
			TagUnknownType_9101_ComponentsConfiguration_Channel_G,
			TagUnknownType_9101_ComponentsConfiguration_Channel_B,
			0,
		},

		TagUnknownType_9101_ComponentsConfiguration_YCBCR: []byte{
			TagUnknownType_9101_ComponentsConfiguration_Channel_Y,
			TagUnknownType_9101_ComponentsConfiguration_Channel_Cb,
			TagUnknownType_9101_ComponentsConfiguration_Channel_Cr,
			0,
		},
	}
)

// TODO(dustin): Rename `UnknownTagValue` to `UndefinedTagValue`.

type UnknownTagValue interface {
	ValueBytes() ([]byte, error)
}

// TODO(dustin): Rename `TagUnknownType_GeneralString` to `TagUnknownType_GeneralString`.

type TagUnknownType_GeneralString string

func (gs TagUnknownType_GeneralString) ValueBytes() (value []byte, err error) {
	return []byte(gs), nil
}

// TODO(dustin): Rename `TagUnknownType_9298_UserComment` to `TagUndefinedType_9298_UserComment`.

type TagUnknownType_9298_UserComment struct {
	EncodingType  int
	EncodingBytes []byte
}

func (uc TagUnknownType_9298_UserComment) String() string {
	var valuePhrase string

	if len(uc.EncodingBytes) <= 8 {
		valuePhrase = fmt.Sprintf("%v", uc.EncodingBytes)
	} else {
		valuePhrase = fmt.Sprintf("%v...", uc.EncodingBytes[:8])
	}

	return fmt.Sprintf("UserComment<SIZE=(%d) ENCODING=[%s] V=%v LEN=(%d)>", len(uc.EncodingBytes), TagUnknownType_9298_UserComment_Encoding_Names[uc.EncodingType], valuePhrase, len(uc.EncodingBytes))
}

func (uc TagUnknownType_9298_UserComment) ValueBytes() (value []byte, err error) {
	encodingTypeBytes, found := TagUnknownType_9298_UserComment_Encodings[uc.EncodingType]
	if found == false {
		log.Panicf("encoding-type not valid for unknown-type tag 9298 (UserComment): (%d)", uc.EncodingType)
	}

	value = make([]byte, len(uc.EncodingBytes)+8)

	copy(value[:8], encodingTypeBytes)
	copy(value[8:], uc.EncodingBytes)

	return value, nil
}

// TODO(dustin): Rename `TagUnknownType_927C_MakerNote` to `TagUndefinedType_927C_MakerNote`.

type TagUnknownType_927C_MakerNote struct {
	MakerNoteType  []byte
	MakerNoteBytes []byte
}

func (mn TagUnknownType_927C_MakerNote) String() string {
	parts := make([]string, 20)
	for i, c := range mn.MakerNoteType {
		parts[i] = fmt.Sprintf("%02x", c)
	}

	h := sha1.New()

	_, err := h.Write(mn.MakerNoteBytes)
	log.PanicIf(err)

	digest := h.Sum(nil)

	return fmt.Sprintf("MakerNote<TYPE-ID=[%s] LEN=(%d) SHA1=[%020x]>", strings.Join(parts, " "), len(mn.MakerNoteBytes), digest)
}

func (uc TagUnknownType_927C_MakerNote) ValueBytes() (value []byte, err error) {
	return uc.MakerNoteBytes, nil
}

// TODO(dustin): Rename `TagUnknownType_9101_ComponentsConfiguration` to `TagUndefinedType_9101_ComponentsConfiguration`.

type TagUnknownType_9101_ComponentsConfiguration struct {
	ConfigurationId    int
	ConfigurationBytes []byte
}

func (cc TagUnknownType_9101_ComponentsConfiguration) String() string {
	return fmt.Sprintf("ComponentsConfiguration<ID=[%s] BYTES=%v>", TagUnknownType_9101_ComponentsConfiguration_Names[cc.ConfigurationId], cc.ConfigurationBytes)
}

func (cc TagUnknownType_9101_ComponentsConfiguration) ValueBytes() (value []byte, err error) {
	return cc.ConfigurationBytes, nil
}

type TagUndefinedType_A302_CfaPattern struct {
	HorizontalRepeat uint16
	VerticalRepeat   uint16
	CfaValue         []byte
}

func (cp TagUndefinedType_A302_CfaPattern) ValueBytes() (value []byte, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = log.Wrap(state.(error))
		}
	}()

	// TODO(dustin): Add test.

	// TODO(dustin): !! byteOrder is not in scope here.
	// -> Clearly, we expect this to be materialized data rather than something that can be changed on the fly.
	// -> EncodeUndefined() currently has all of the encoding logic embedded in it. It'd be better to move all of the encoding and decoding to the individual types
	// -> ...which we can then break out to separate files in a subpackage, which will be cleaner and easier to maintain.

	b := new(bytes.Buffer)

	err = binary.Write(b, byteOrder, cp.HorizontalRepeat)
	log.PanicIf(err)

	err = binary.Write(b, byteOrder, cp.VerticalRepeat)
	log.PanicIf(err)

	_, err = b.Write(cp.CfaValue)
	log.PanicIf(err)

	return b.Bytes(), nil
}

type TagUndefinedType_A20C_SpatialFrequencyResponse struct {
	Columns     uint16
	Rows        uint16
	ColumnNames []string
	Values      []Rational
}

func (sfr TagUndefinedType_A20C_SpatialFrequencyResponse) ValueBytes() (value []byte, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = log.Wrap(state.(error))
		}
	}()

	// TODO(dustin): Add reciprocal test.

	b := new(bytes.Buffer)

	err = binary.Write(b, byteOrder, sfr.Columns)
	log.PanicIf(err)

	err = binary.Write(b, byteOrder, sfr.Rows)
	log.PanicIf(err)

	for _, name := range sfr.ColumnNames {
		_, err := b.WriteString(name)
		log.PanicIf(err)

		err = b.WriteByte(0)
		log.PanicIf(err)
	}

	ve := NewValueEncoder(byteOrder)

	ed, err := ve.Encode(sfr.Values)
	log.PanicIf(err)

	_, err = b.Write(ed.Encoded)
	log.PanicIf(err)

	return b.Bytes(), nil
}

type TagUndefinedType_8828_OECF struct {
	Columns     uint16
	Rows        uint16
	ColumnNames []string
	Values      []SignedRational
}

func (uc TagUndefinedType_8828_OECF) ValueBytes() (value []byte, err error) {

	// TODO(dustin): !! Finish.

}

// TODO(dustin): Rename `EncodeUnknown_9286` to `EncodeUndefined_9286`.

func EncodeUnknown_9286(uc TagUnknownType_9298_UserComment) (encoded []byte, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = log.Wrap(state.(error))
		}
	}()

	b := new(bytes.Buffer)

	encodingTypeBytes := TagUnknownType_9298_UserComment_Encodings[uc.EncodingType]

	_, err = b.Write(encodingTypeBytes)
	log.PanicIf(err)

	_, err = b.Write(uc.EncodingBytes)
	log.PanicIf(err)

	return b.Bytes(), nil
}

type EncodeableUndefinedValue struct {
	IfdPath    string
	TagId      uint16
	Parameters interface{}
}

func EncodeUndefined(ifdPath string, tagId uint16, value interface{}) (ed EncodedData, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = log.Wrap(state.(error))
		}
	}()

	// TODO(dustin): !! Finish implementing these. This allows us to support writing custom undefined-tag values.

	if ifdPath == IfdPathStandardExif {
		if tagId == 0x9286 {
			encoded, err := EncodeUnknown_9286(value.(TagUnknownType_9298_UserComment))
			log.PanicIf(err)

			ed.Type = TypeUndefined
			ed.Encoded = encoded
			ed.UnitCount = uint32(len(encoded))

			return ed, nil
		}
	}

	log.Panicf("undefined value not encodable: %s (0x%02x)", ifdPath, tagId)

	// Never called.
	return EncodedData{}, nil
}

// TODO(dustin): Rename `TagUnknownType_UnknownValue` to `TagUndefinedType_UnknownValue`.

type TagUnknownType_UnknownValue []byte

func (tutuv TagUnknownType_UnknownValue) String() string {
	parts := make([]string, len(tutuv))
	for i, c := range tutuv {
		parts[i] = fmt.Sprintf("%02x", c)
	}

	h := sha1.New()

	_, err := h.Write(tutuv)
	log.PanicIf(err)

	digest := h.Sum(nil)

	return fmt.Sprintf("Unknown<DATA=[%s] LEN=(%d) SHA1=[%020x]>", strings.Join(parts, " "), len(tutuv), digest)
}

// UndefinedValue knows how to resolve the value for most unknown-type tags.
func UndefinedValue(ifdPath string, tagId uint16, valueContext interface{}, byteOrder binary.ByteOrder) (value interface{}, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = log.Wrap(state.(error))
		}
	}()

	// TODO(dustin): Stop exporting this. Use `(*ValueContext).Undefined()`.

	var valueContextPtr *ValueContext

	if vc, ok := valueContext.(*ValueContext); ok == true {
		// Legacy usage.

		valueContextPtr = vc
	} else {
		// Standard usage.

		valueContextValue := valueContext.(ValueContext)
		valueContextPtr = &valueContextValue
	}

	typeLogger.Debugf(nil, "UndefinedValue: IFD-PATH=[%s] TAG-ID=(0x%02x)", ifdPath, tagId)

	// TODO(dustin): Write unit-tests for all of these
	if ifdPath == IfdPathStandardExif {
		if tagId == 0x9000 {
			// ExifVersion

			valueContextPtr.SetUnknownValueType(TypeAsciiNoNul)

			valueString, err := valueContextPtr.ReadAsciiNoNul()
			log.PanicIf(err)

			return TagUnknownType_GeneralString(valueString), nil
		} else if tagId == 0xa000 {
			// FlashpixVersion

			valueContextPtr.SetUnknownValueType(TypeAsciiNoNul)

			valueString, err := valueContextPtr.ReadAsciiNoNul()
			log.PanicIf(err)

			return TagUnknownType_GeneralString(valueString), nil
		} else if tagId == 0x9286 {
			// UserComment

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			unknownUc := TagUnknownType_9298_UserComment{
				EncodingType:  TagUnknownType_9298_UserComment_Encoding_UNDEFINED,
				EncodingBytes: []byte{},
			}

			encoding := valueBytes[:8]
			for encodingIndex, encodingBytes := range TagUnknownType_9298_UserComment_Encodings {
				if bytes.Compare(encoding, encodingBytes) == 0 {
					uc := TagUnknownType_9298_UserComment{
						EncodingType:  encodingIndex,
						EncodingBytes: valueBytes[8:],
					}

					return uc, nil
				}
			}

			typeLogger.Warningf(nil, "User-comment encoding not valid. Returning 'unknown' type (the default).")
			return unknownUc, nil
		} else if tagId == 0x927c {
			// MakerNote
			// TODO(dustin): !! This is the Wild Wild West. This very well might be a child IFD, but any and all OEM's define their own formats. If we're going to be writing changes and this is complete EXIF (which may not have the first eight bytes), it might be fine. However, if these are just IFDs they'll be relative to the main EXIF, this will invalidate the MakerNote data for IFDs and any other implementations that use offsets unless we can interpret them all. It be best to return to this later and just exclude this from being written for now, though means a loss of a wealth of image metadata.
			//                  -> We can also just blindly try to interpret as an IFD and just validate that it's looks good (maybe it will even have a 'next ifd' pointer that we can validate is 0x0).

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			// TODO(dustin): Doesn't work, but here as an example.
			//             ie := NewIfdEnumerate(valueBytes, byteOrder)

			// // TODO(dustin): !! Validate types (might have proprietary types, but it might be worth splitting the list between valid and not valid; maybe fail if a certain proportion are invalid, or maybe aren't less then a certain small integer)?
			//             ii, err := ie.Collect(0x0)

			//             for _, entry := range ii.RootIfd.Entries {
			//                 fmt.Printf("ENTRY: 0x%02x %d\n", entry.TagId, entry.TagType)
			//             }

			mn := TagUnknownType_927C_MakerNote{
				MakerNoteType: valueBytes[:20],

				// MakerNoteBytes has the whole length of bytes. There's always
				// the chance that the first 20 bytes includes actual data.
				MakerNoteBytes: valueBytes,
			}

			return mn, nil
		} else if tagId == 0x9101 {
			// ComponentsConfiguration

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			for configurationId, configurationBytes := range TagUnknownType_9101_ComponentsConfiguration_Configurations {
				if bytes.Compare(valueBytes, configurationBytes) == 0 {
					cc := TagUnknownType_9101_ComponentsConfiguration{
						ConfigurationId:    configurationId,
						ConfigurationBytes: valueBytes,
					}

					return cc, nil
				}
			}

			cc := TagUnknownType_9101_ComponentsConfiguration{
				ConfigurationId:    TagUnknownType_9101_ComponentsConfiguration_OTHER,
				ConfigurationBytes: valueBytes,
			}

			return cc, nil
		} else if tagId == 0xa302 {
			// CFAPattern

			// TODO(dustin): Add test using known good data.

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			cp := TagUndefinedType_A302_CfaPattern{}

			cp.HorizontalRepeat = byteOrder.Uint16(valueBytes[0:2])
			cp.VerticalRepeat = byteOrder.Uint16(valueBytes[2:4])

			expectedLength := int(cp.HorizontalRepeat * cp.VerticalRepeat)
			cp.CfaValue = valueBytes[4 : 4+expectedLength]

			return cp, nil
		} else if tagId == 0xa20c {
			// SpatialFrequencyResponse

			// TODO(dustin): Add test using known good data.

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			sfr := TagUndefinedType_A20C_SpatialFrequencyResponse{}

			sfr.Columns = byteOrder.Uint16(valueBytes[0:2])
			sfr.Rows = byteOrder.Uint16(valueBytes[2:4])

			columnNames := make([]string, cp.Columns)

			// startAt is where the current column name starts.
			startAt := 4

			// offset is our current position.
			offset := 4

			currentColumnNumber := 0

			for currentColumnNumber < cp.Columns {
				if valueBytes[offset] == 0 {
					columnName := string(valueBytes[startAt:offset])
					if len(columnName) == 0 {
						log.Panicf("SFR column (%d) has zero length", currentColumnNumber)
					}

					columnNames[currentColumnNumber] = columnName
					currentColumnNumber++

					offset++
					startAt = offset
					continue
				}

				offset++
			}

			sfr.ColumnNames = columnNames

			rawRationalBytes := valueBytes[offset:]

			rationalSize := TypeRational.Size()
			if len(rawRationalBytes)%rationalSize > 0 {
				log.Panicf("SFR rationals not aligned: (%d) % (%d) > 0", len(rawRationalBytes), rationalSize)
			}

			rationalCount := len(rawRationalBytes) / rationalSize

			items, err := parser.ParseRationals(rawRationalBytes, rationalCount, byteOrder)
			log.PanicIf(err)

			sfr.Values = items

			return sfr, nil
		} else if tagId == 0x8828 {
			// OECF

			// TODO(dustin): Add test using known good data.

			valueContextPtr.SetUnknownValueType(TypeByte)

			valueBytes, err := valueContextPtr.ReadBytes()
			log.PanicIf(err)

			oecf := TagUndefinedType_8828_OECF{}

			oecf.Columns = byteOrder.Uint16(valueBytes[0:2])
			oecf.Rows = byteOrder.Uint16(valueBytes[2:4])

			columnNames := make([]string, cp.Columns)

			// startAt is where the current column name starts.
			startAt := 4

			// offset is our current position.
			offset := 4

			currentColumnNumber := 0

			for currentColumnNumber < cp.Columns {
				if valueBytes[offset] == 0 {
					columnName := string(valueBytes[startAt:offset])
					if len(columnName) == 0 {
						log.Panicf("SFR column (%d) has zero length", currentColumnNumber)
					}

					columnNames[currentColumnNumber] = columnName
					currentColumnNumber++

					offset++
					startAt = offset
					continue
				}

				offset++
			}

			oecf.ColumnNames = columnNames

			rawRationalBytes := valueBytes[offset:]

			rationalSize := TypeSignedRational.Size()
			if len(rawRationalBytes)%rationalSize > 0 {
				log.Panicf("OECF signed-rationals not aligned: (%d) % (%d) > 0", len(rawRationalBytes), rationalSize)
			}

			rationalCount := len(rawRationalBytes) / rationalSize

			items, err := parser.ParseSignedRationals(rawRationalBytes, rationalCount, byteOrder)
			log.PanicIf(err)

			oecf.Values = items

			return oecf, nil
		}
	} else if ifdPath == IfdPathStandardGps {
		if tagId == 0x001c {
			// GPSAreaInformation

			valueContextPtr.SetUnknownValueType(TypeAsciiNoNul)

			valueString, err := valueContextPtr.ReadAsciiNoNul()
			log.PanicIf(err)

			return TagUnknownType_GeneralString(valueString), nil
		} else if tagId == 0x001b {
			// GPSProcessingMethod

			valueContextPtr.SetUnknownValueType(TypeAsciiNoNul)

			valueString, err := valueContextPtr.ReadAsciiNoNul()
			log.PanicIf(err)

			return TagUnknownType_GeneralString(valueString), nil
		}
	} else if ifdPath == IfdPathStandardExifIop {
		if tagId == 0x0002 {
			// InteropVersion

			valueContextPtr.SetUnknownValueType(TypeAsciiNoNul)

			valueString, err := valueContextPtr.ReadAsciiNoNul()
			log.PanicIf(err)

			return TagUnknownType_GeneralString(valueString), nil
		}
	}

	// TODO(dustin): !! Still need to do:
	//
	// complex: 0x8828
	// long: 0xa301, 0xa300
	//
	// 0xa40b is device-specific and unhandled.
	//
	// See https://github.com/dsoprea/go-exif/issues/26.

	// We have no choice but to return the error. We have no way of knowing how
	// much data there is without already knowing what data-type this tag is.
	return nil, ErrUnhandledUnknownTypedTag
}
