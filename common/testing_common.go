package exifcommon

import (
	"os"
	"path"

	"encoding/binary"
	"io/ioutil"

	log "github.com/dsoprea/go-logging"
)

var (
	assetsPath        = ""
	testImageFilepath = ""
	testExifData      = make([]byte, 0)
	moduleRootPath    = ""

	// EncodeDefaultByteOrder is the default byte-order for encoding operations.
	EncodeDefaultByteOrder = binary.BigEndian

	// Default byte order for tests.
	TestDefaultByteOrder = binary.BigEndian
)

func GetModuleRootPath() string {
	if moduleRootPath != "" {
		return moduleRootPath
	}

	moduleRootPath := os.Getenv("EXIF_MODULE_ROOT_PATH")
	if moduleRootPath != "" {
		return moduleRootPath
	}

	currentWd, err := os.Getwd()
	log.PanicIf(err)
	return currentWd
}

func getTestAssetsPath() string {
	if assetsPath == "" {
		moduleRootPath := GetModuleRootPath()
		assetsPath = path.Join(moduleRootPath, "assets")
	}

	return assetsPath
}

func getTestImageFilepath() string {
	if testImageFilepath == "" {
		assetsPath := getTestAssetsPath()
		testImageFilepath = path.Join(assetsPath, "NDM_8901.jpg")
	}

	return testImageFilepath
}

func getTestExifData() []byte {
	assetsPath := getTestAssetsPath()
	filepath := path.Join(assetsPath, "NDM_8901.jpg.exif")

	var err error

	testExifData, err = ioutil.ReadFile(filepath)
	log.PanicIf(err)

	return testExifData
}