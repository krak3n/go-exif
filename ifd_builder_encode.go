package exif

import (
    "bytes"
    "fmt"
    "strings"

    "encoding/binary"

    "github.com/dsoprea/go-logging"
)

const (
    // Tag-ID + Tag-Type + Unit-Count + Value/Offset.
    IfdTagEntrySize = uint32(2 + 2 + 4 + 4)
)

type ByteWriter struct {
    b *bytes.Buffer
    byteOrder binary.ByteOrder
}

func NewByteWriter(b *bytes.Buffer, byteOrder binary.ByteOrder) (bw *ByteWriter) {
    return &ByteWriter{
        b: b,
        byteOrder: byteOrder,
    }
}

func (bw ByteWriter) writeAsBytes(value interface{}) (err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    err = binary.Write(bw.b, bw.byteOrder, value)
    log.PanicIf(err)

    return nil
}

func (bw ByteWriter) WriteUint32(value uint32) (err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    err = bw.writeAsBytes(value)
    log.PanicIf(err)

    return nil
}

func (bw ByteWriter) WriteUint16(value uint16) (err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    err = bw.writeAsBytes(value)
    log.PanicIf(err)

    return nil
}

func (bw ByteWriter) WriteFourBytes(value []byte) (err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    len_ := len(value)
    if len_ != 4 {
        log.Panicf("value is not four-bytes: (%d)", len_)
    }

    _, err = bw.b.Write(value)
    log.PanicIf(err)

    return nil
}


// ifdOffsetIterator keeps track of where the next IFD should be written by
// keeping track of where the offsets start, the data that has been added, and
// bumping the offset *when* the data is added.
type ifdDataAllocator struct {
    offset uint32
    b bytes.Buffer
}

func newIfdDataAllocator(ifdDataAddressableOffset uint32) *ifdDataAllocator{
    return &ifdDataAllocator{
        offset: ifdDataAddressableOffset,
    }
}

func (ida *ifdDataAllocator) Allocate(value []byte) (offset uint32, err error) {
    _, err = ida.b.Write(value)
    log.PanicIf(err)

    offset = ida.offset
    ida.offset += uint32(len(value))

    return offset, nil
}

func (ida *ifdDataAllocator) NextOffset() uint32 {
    return ida.offset
}

func (ida *ifdDataAllocator) Bytes() []byte {
    return ida.b.Bytes()
}


// IfdByteEncoder converts an IB to raw bytes (for writing) while also figuring
// out all of the allocations and indirection that is required for extended
// data.
type IfdByteEncoder struct {
    // journal holds a list of actions taken while encoding.
    journal [][3]string
}

func NewIfdByteEncoder() (ibe *IfdByteEncoder) {
    return &IfdByteEncoder{
        journal: make([][3]string, 0),
    }
}

func (ibe *IfdByteEncoder) Journal() [][3]string {
    return ibe.journal
}

func (ibe *IfdByteEncoder) TableSize(entryCount int) uint32 {
    // Tag-Count + (Entry-Size * Entry-Count) + Next-IFD-Offset.
    return uint32(2) + (IfdTagEntrySize * uint32(entryCount)) + uint32(4)
}

func (ibe *IfdByteEncoder) pushToJournal(where, direction, format string, args ...interface{}) {
    event := [3]string {
        direction,
        where,
        fmt.Sprintf(format, args...),
    }

    ibe.journal = append(ibe.journal, event)
}

// PrintJournal prints a hierarchical representation of the steps taken during
// encoding.
func (ibe *IfdByteEncoder) PrintJournal() {
    maxWhereLength := 0
    for _, event := range ibe.journal {
        where := event[1]

        len_ := len(where)
        if len_ > maxWhereLength {
            maxWhereLength = len_
        }
    }

    level := 0
    for i, event := range ibe.journal {
        direction := event[0]
        where := event[1]
        message := event[2]

        if direction != ">" && direction != "<" && direction != "-" {
            log.Panicf("journal operation not valid: [%s]", direction)
        }

        if direction == "<" {
            if level <= 0 {
                log.Panicf("journal operations unbalanced (too many closes)")
            }

            level--
        }

        indent := strings.Repeat("  ", level)

        fmt.Printf("%3d %s%s %s: %s\n", i, indent, direction, where, message)

        if direction == ">" {
            level++
        }
    }

    if level != 0 {
        log.Panicf("journal operations unbalanced (too many opens)")
    }
}

// encodeTagToBytes encodes the given tag to a byte stream. If
// `nextIfdOffsetToWrite` is more than (0), recurse into child IFDs
// (`nextIfdOffsetToWrite` is required in order for them to know where the its
// IFD data will be written, in order for them to know the offset of where
// their allocated-data block will start, which follows right behind).
func (ibe *IfdByteEncoder) encodeTagToBytes(ib *IfdBuilder, bt *builderTag, bw *ByteWriter, ida *ifdDataAllocator, nextIfdOffsetToWrite uint32) (childIfdBlock []byte, err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    // Write tag-ID.
    err = bw.WriteUint16(bt.tagId)
    log.PanicIf(err)

    // Works for both values and child IFDs (which have an official size of
    // LONG).
    err = bw.WriteUint16(bt.typeId)
    log.PanicIf(err)

    // Write unit-count.

    if bt.value.IsBytes() == true {
        effectiveType := bt.typeId
        if bt.typeId == TypeUndefined {
            effectiveType = TypeByte
        }

        // It's a non-unknown value.Calculate the count of values of
        // the type that we're writing and the raw bytes for the whole list.

        typeSize := uint32(TagTypeSize(effectiveType))

        valueBytes := bt.value.Bytes()

        len_ := len(valueBytes)
        unitCount := uint32(len_) / typeSize
        remainder := uint32(len_) % typeSize

        if remainder > 0 {
            log.Panicf("tag value of (%d) bytes not evenly divisible by type-size (%d)", len_, typeSize)
        }

        err = bw.WriteUint32(unitCount)
        log.PanicIf(err)

        // Write four-byte value/offset.

        if len_ > 4 {
            offset, err := ida.Allocate(valueBytes)
            log.PanicIf(err)

            err = bw.WriteUint32(offset)
            log.PanicIf(err)
        } else {
            fourBytes := make([]byte, 4)
            copy(fourBytes, valueBytes)

            err = bw.WriteFourBytes(fourBytes)
            log.PanicIf(err)
        }
    } else {
        if bt.value.IsIb() == false {
            log.Panicf("tag value is not a byte-slice but also not a child IB: %v", bt)
        }

        // Write unit-count (one LONG representing one offset).
        err = bw.WriteUint32(1)
        log.PanicIf(err)

        if nextIfdOffsetToWrite > 0 {
            var err error

            ibe.pushToJournal("encodeTagToBytes", ">", "[%s]->[%s]", ib.ii.IfdName, bt.value.Ib().ii.IfdName)

            // Create the block of IFD data and everything it requires.
            childIfdBlock, err = ibe.encodeAndAttachIfd(bt.value.Ib(), nextIfdOffsetToWrite)
            log.PanicIf(err)

            ibe.pushToJournal("encodeTagToBytes", "<", "[%s]->[%s]", bt.value.Ib().ii.IfdName, ib.ii.IfdName)

            // Use the next-IFD offset for it. The IFD will actually get
            // attached after we return.
            err = bw.WriteUint32(nextIfdOffsetToWrite)
            log.PanicIf(err)

        } else {
            // No child-IFDs are to be allocated. Finish the entry with a NULL
            // pointer.

            ibe.pushToJournal("encodeTagToBytes", "-", "*Not* descending to child: [%s]", bt.value.Ib().ii.IfdName)

            err = bw.WriteUint32(0)
            log.PanicIf(err)
        }
    }

    return childIfdBlock, nil
}

// encodeIfdToBytes encodes the given IB to a byte-slice. We are given the
// offset at which this IFD will be written. This method is used called both to
// pre-determine how big the table is going to be (so that we can calculate the
// address to allocate data at) as well as to write the final table.
//
// It is necessary to fully realize the table in order to predetermine its size
// because it is not enough to know the size of the table: If there are child
// IFDs, we will not be able to allocate them without first knowing how much
// data we need to allocate for the current IFD.
func (ibe *IfdByteEncoder) encodeIfdToBytes(ib *IfdBuilder, ifdAddressableOffset uint32, nextIfdOffsetToWrite uint32, setNextIb bool) (data []byte, tableSize uint32, dataSize uint32, childIfdSizes []uint32, err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    ibe.pushToJournal("encodeIfdToBytes", ">", "%s", ib)

    tableSize = ibe.TableSize(len(ib.tags))

    b := new(bytes.Buffer)
    bw := NewByteWriter(b, ib.byteOrder)

    // Write tag count.
    err = bw.WriteUint16(uint16(len(ib.tags)))
    log.PanicIf(err)

    ida := newIfdDataAllocator(ifdAddressableOffset)

    childIfdBlocks := make([][]byte, 0)

    // Write raw bytes for each tag entry. Allocate larger data to be referred
    // to in the follow-up data-block as required. Any "unknown"-byte tags that
    // we can't parse will not be present here (using AddTagsFromExisting(), at
    // least).
    for _, bt := range ib.tags {
        childIfdBlock, err := ibe.encodeTagToBytes(ib, &bt, bw, ida, nextIfdOffsetToWrite)
        log.PanicIf(err)

        if childIfdBlock != nil {
            if nextIfdOffsetToWrite == 0 {
                log.Panicf("no IFD offset provided for child-IFDs; no new child-IFDs permitted")
            }

            nextIfdOffsetToWrite += uint32(len(childIfdBlock))
            childIfdBlocks = append(childIfdBlocks, childIfdBlock)
        }
    }

    dataBytes := ida.Bytes()
    dataSize = uint32(len(dataBytes))

    childIfdSizes = make([]uint32, len(childIfdBlocks))
    childIfdsTotalSize := uint32(0)
    for i, childIfdBlock := range childIfdBlocks {
        len_ := uint32(len(childIfdBlock))
        childIfdSizes[i] = len_
        childIfdsTotalSize += len_
    }

    // N the link from this IFD to the next IFD that will be written in the
    // next cycle.
    if setNextIb == true {
        // Write address of next IFD in chain. This will be the original
        // allocation offset plus the size of everything we have allocated for
        // this IFD and its child-IFDs.
        //
        // It is critical that this number is stepped properly. We experienced
        // an issue whereby it first looked like we were duplicating the IFD and
        // then that we were duplicating the tags in the wrong IFD, and then
        // finally we determined that the next-IFD offset for the first IFD was
        // accidentally pointing back to the EXIF IFD, so we were visiting it
        // twice when visiting through the tags after decoding. It was an
        // expensive bug to find.

        ibe.pushToJournal("encodeIfdToBytes", "-", "Setting 'next' IFD to (0x%08x).", nextIfdOffsetToWrite)

        err := bw.WriteUint32(nextIfdOffsetToWrite)
        log.PanicIf(err)
    } else {
        err := bw.WriteUint32(0)
        log.PanicIf(err)
    }

    _, err = b.Write(dataBytes)
    log.PanicIf(err)

    // Append any child IFD blocks after our table and data blocks. These IFDs
    // were equipped with the appropriate offset information so it's expected
    // that all offsets referred to by these will be correct.
    //
    // Note that child-IFDs are append after the current IFD and before the
    // next IFD, as opposed to the root IFDs, which are chained together but
    // will be interrupted by these child-IFDs (which is expected, per the
    // standard).

    for _, childIfdBlock := range childIfdBlocks {
        _, err = b.Write(childIfdBlock)
        log.PanicIf(err)
    }

    ibe.pushToJournal("encodeIfdToBytes", "<", "%s", ib)

    return b.Bytes(), tableSize, dataSize, childIfdSizes, nil
}

// encodeAndAttachIfd is a reentrant function that processes the IFD chain.
func (ibe *IfdByteEncoder) encodeAndAttachIfd(ib *IfdBuilder, ifdAddressableOffset uint32) (data []byte, err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    ibe.pushToJournal("encodeAndAttachIfd", ">", "%s", ib)

    if len(ib.tags) == 0 {
        log.Panicf("trying to encode an IfdBuilder that doesn't have any tags")
    }

    b := new(bytes.Buffer)

    nextIfdOffsetToWrite := uint32(0)
    i := 0
    for thisIb := ib; thisIb != nil; thisIb = thisIb.nextIb {
        // Do a dry-run in order to pre-determine its size requirement.

        ibe.pushToJournal("encodeAndAttachIfd", ">", "Beginning encoding process: (%d) [%s] NEXT-IFD-OFFSET-TO-WRITE=(0x%08x)", i, thisIb.ii.IfdName, nextIfdOffsetToWrite)

        ibe.pushToJournal("encodeAndAttachIfd", ">", "Calculating size: (%d) [%s]", i, thisIb.ii.IfdName)

        _, tableSize, allocatedDataSize, _, err := ibe.encodeIfdToBytes(thisIb, ifdAddressableOffset, 0, false)
        log.PanicIf(err)

        ibe.pushToJournal("encodeAndAttachIfd", "<", "Finished calculating size: (%d) [%s]", i, thisIb.ii.IfdName)

        ifdAddressableOffset += tableSize
        nextIfdOffsetToWrite = ifdAddressableOffset + allocatedDataSize

        // Write our IFD as well as any child-IFDs (now that we know the offset
        // where new IFDs and their data will be allocated).

        setNextIb := thisIb.nextIb != nil

        ibe.pushToJournal("encodeAndAttachIfd", ">", "Encoding starting: (%d) [%s] NEXT-IFD-OFFSET-TO-WRITE=(0x%08x)", i, thisIb.ii.IfdName, nextIfdOffsetToWrite)

        tableAndAllocated, tableSize, allocatedDataSize, childIfdSizes, err :=
            ibe.encodeIfdToBytes(thisIb, ifdAddressableOffset, nextIfdOffsetToWrite, setNextIb)

        log.PanicIf(err)

        ibe.pushToJournal("encodeAndAttachIfd", "<", "Encoding done: (%d) [%s]", i, thisIb.ii.IfdName)

        totalChildIfdSize := uint32(0)
        for _, childIfdSize := range childIfdSizes {
            totalChildIfdSize += childIfdSize
        }

        if len(tableAndAllocated) != int(tableSize + allocatedDataSize + totalChildIfdSize) {
            log.Panicf("IFD table and data is not a consistent size: (%d) != (%d)", len(tableAndAllocated), tableSize + allocatedDataSize + totalChildIfdSize)
        }

        _, err = b.Write(tableAndAllocated)
        log.PanicIf(err)

// TODO(dustin): !! The core problem is the offset being the same for two IFDs.
        // Advance past what we've allocated, thus far.
        ifdAddressableOffset = nextIfdOffsetToWrite

        ibe.pushToJournal("encodeAndAttachIfd", "<", "Finishing encoding process: (%d) [%s] [FINAL:] NEXT-IFD-OFFSET-TO-WRITE=(0x%08x)", i, ib.ii.IfdName, nextIfdOffsetToWrite)

        i++
    }

    ibe.pushToJournal("encodeAndAttachIfd", "<", "%s", ib)

    return b.Bytes(), nil
}

// EncodeToExifPayload is the base encoding step that transcribes the entire IB
// structure to its on-disk layout.
func (ibe *IfdByteEncoder) EncodeToExifPayload(ib *IfdBuilder) (data []byte, err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    data, err = ibe.encodeAndAttachIfd(ib, ExifDefaultFirstIfdOffset)
    log.PanicIf(err)

    return data, nil
}

// EncodeToExif calls EncodeToExifPayload and then packages the result into a
// complete EXIF block.
func (ibe *IfdByteEncoder) EncodeToExif(ib *IfdBuilder) (data []byte, err error) {
    defer func() {
        if state := recover(); state != nil {
            err = log.Wrap(state.(error))
        }
    }()

    encodedIfds, err := ibe.EncodeToExifPayload(ib)
    log.PanicIf(err)

    // Wrap the IFD in a formal EXIF block.

    b := new(bytes.Buffer)

    headerBytes, err := BuildExifHeader(ib.byteOrder, ExifDefaultFirstIfdOffset)
    log.PanicIf(err)

    _, err = b.Write(headerBytes)
    log.PanicIf(err)

    _, err = b.Write(encodedIfds)
    log.PanicIf(err)

    return b.Bytes(), nil
}
