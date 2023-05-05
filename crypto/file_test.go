package crypto

import (
	"os"
	"reflect"
	"testing"
)

func assert(result any, expected any, msg string, t *testing.T) {
	if result != expected {
		t.Error(msg)
	}

}

func TestFile1(t *testing.T) {
	f := &EncryptedFile{}
	key := []byte("1234567890123456")
	err := f.Open("/tmp/goTest.txt", os.O_RDWR|os.O_TRUNC, 0755, key)
	assert(err, nil, "open error", t)

	data := []byte("123456789ABCEDF123456789ABCEDF123")
	n, err := f.Write(data)
	assert(err, nil, "write error", t)
	assert(n, len(data), "write n error", t)

	ret, err := f.Seek(0, 0)
	assert(err, nil, "seek error", t)
	assert(ret, int64(0), "seek ret error", t)

	buffer := make([]byte, 10)
	n, err = f.Read(buffer)
	assert(err, nil, "read error", t)
	assert(n, len(buffer), "read n error", t)
	t.Log(n)

	isEqual := reflect.DeepEqual(buffer, data[:len(buffer)])
	assert(isEqual, true, "read data error", t)

	err = f.Close()
	assert(err, nil, "close error", t)
}
