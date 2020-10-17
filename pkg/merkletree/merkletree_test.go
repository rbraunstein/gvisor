// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestLayout(t *testing.T) {
	testCases := []struct {
		dataSize              int64
		hashAlgorithms        int
		dataAndTreeInSameFile bool
		expectedDigestSize    int64
		expectedLevelOffset   []int64
	}{
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 4 * usermem.PageSize, 5 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 247 * usermem.PageSize, 248 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 249 * usermem.PageSize, 250 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 64 * usermem.PageSize, 65 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4128 * usermem.PageSize, 4129 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4160 * usermem.PageSize, 4161 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			l, err := InitLayout(tc.dataSize, tc.hashAlgorithms, tc.dataAndTreeInSameFile)
			if err != nil {
				t.Fatalf("Failed to InitLayout: %v", err)
			}
			if l.blockSize != int64(usermem.PageSize) {
				t.Errorf("Got blockSize %d, want %d", l.blockSize, usermem.PageSize)
			}
			if l.digestSize != tc.expectedDigestSize {
				t.Errorf("Got digestSize %d, want %d", l.digestSize, sha256DigestSize)
			}
			if l.numLevels() != len(tc.expectedLevelOffset) {
				t.Errorf("Got levels %d, want %d", l.numLevels(), len(tc.expectedLevelOffset))
			}
			for i := 0; i < l.numLevels() && i < len(tc.expectedLevelOffset); i++ {
				if l.levelOffset[i] != tc.expectedLevelOffset[i] {
					t.Errorf("Got levelStart[%d] %d, want %d", i, l.levelOffset[i], tc.expectedLevelOffset[i])
				}
			}
		})
	}
}

const (
	defaultName = "merkle_test"
	defaultMode = 0644
	defaultUID  = 0
	defaultGID  = 0
)

// bytesReadWriter is used to read from/write to/seek in a byte array. Unlike
// bytes.Buffer, it keeps the whole buffer during read so that it can be reused.
type bytesReadWriter struct {
	// bytes contains the underlying byte array.
	bytes []byte
	// readPos is the currently location for Read. Write always appends to
	// the end of the array.
	readPos int
}

func (brw *bytesReadWriter) Write(p []byte) (int, error) {
	brw.bytes = append(brw.bytes, p...)
	return len(p), nil
}

func (brw *bytesReadWriter) ReadAt(p []byte, off int64) (int, error) {
	bytesRead := copy(p, brw.bytes[off:])
	if bytesRead == 0 {
		return bytesRead, io.EOF
	}
	return bytesRead, nil
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		data           []byte
		hashAlgorithms int
		expectedHash   []byte
	}{
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{223, 189, 205, 68, 98, 218, 113, 7, 41, 233, 46, 166, 223, 35, 83, 87, 161, 45, 63, 32, 59, 171, 129, 80, 149, 74, 234, 132, 161, 35, 61, 103},
		},
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{227, 189, 121, 17, 100, 232, 169, 0, 71, 251, 255, 155, 150, 113, 149, 231, 22, 166, 17, 111, 87, 151, 57, 247, 5, 61, 89, 230, 182, 246, 102, 62, 184, 173, 164, 69, 32, 79, 176, 199, 187, 26, 134, 125, 239, 153, 224, 151, 237, 157, 2, 169, 148, 34, 234, 164, 51, 121, 54, 228, 59, 149, 4, 226},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{214, 160, 137, 118, 150, 81, 233, 191, 155, 11, 41, 165, 100, 202, 172, 180, 25, 135, 252, 139, 165, 221, 86, 51, 235, 46, 152, 159, 209, 99, 160, 10},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{220, 114, 239, 161, 248, 191, 247, 51, 119, 211, 134, 33, 203, 174, 69, 184, 130, 132, 30, 141, 105, 90, 234, 66, 220, 79, 72, 161, 116, 101, 76, 66, 232, 158, 64, 150, 50, 173, 169, 208, 244, 237, 93, 180, 23, 163, 117, 179, 249, 124, 179, 135, 22, 5, 91, 28, 72, 13, 161, 208, 148, 248, 25, 51},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{212, 244, 198, 19, 218, 223, 145, 120, 40, 250, 210, 44, 49, 7, 80, 94, 13, 93, 68, 140, 47, 129, 54, 184, 172, 238, 108, 231, 254, 205, 238, 167},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{67, 124, 0, 139, 172, 188, 95, 101, 5, 221, 121, 110, 234, 147, 61, 39, 70, 39, 2, 138, 154, 39, 96, 72, 13, 181, 152, 174, 129, 217, 252, 123, 161, 72, 251, 129, 159, 116, 74, 246, 196, 240, 179, 149, 247, 207, 85, 103, 226, 4, 6, 191, 183, 83, 101, 102, 152, 163, 66, 226, 210, 161, 63, 112},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{246, 233, 20, 171, 23, 54, 209, 183, 68, 159, 190, 183, 150, 91, 47, 12, 240, 209, 79, 118, 180, 202, 211, 218, 136, 123, 10, 234, 230, 99, 42, 157},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{152, 208, 225, 159, 11, 10, 5, 106, 164, 41, 103, 212, 122, 192, 197, 221, 242, 117, 240, 252, 83, 45, 224, 236, 194, 124, 192, 4, 238, 94, 200, 55, 48, 153, 243, 123, 92, 180, 198, 113, 64, 34, 78, 71, 134, 5, 60, 64, 4, 166, 85, 3, 189, 211, 64, 167, 131, 187, 102, 232, 112, 190, 191, 9},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d:%v", len(tc.data), tc.data[0]), func(t *testing.T) {
			for _, dataAndTreeInSameFile := range []bool{false, true} {
				var tree bytesReadWriter
				params := GenerateParams{
					Size:                  int64(len(tc.data)),
					Name:                  defaultName,
					Mode:                  defaultMode,
					UID:                   defaultUID,
					GID:                   defaultGID,
					Children:              map[string]bool{},
					HashAlgorithms:        tc.hashAlgorithms,
					TreeReader:            &tree,
					TreeWriter:            &tree,
					DataAndTreeInSameFile: dataAndTreeInSameFile,
				}
				if dataAndTreeInSameFile {
					tree.Write(tc.data)
					params.File = &tree
				} else {
					params.File = &bytesReadWriter{
						bytes: tc.data,
					}
				}
				hash, err := Generate(&params)
				if err != nil {
					t.Fatalf("Got err: %v, want nil", err)
				}

				if !bytes.Equal(hash, tc.expectedHash) {
					t.Errorf("Got hash: %v, want %v", hash, tc.expectedHash)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	// The input data has size dataSize. The portion to be verified ranges from
	// verifyStart with verifySize. A bit is flipped in outOfRangeByteIndex to
	// confirm that modifications outside the verification range does not cause
	// issue. And a bit is flipped in modifyByte to confirm that
	// modifications in the verification range is caught during verification.
	testCases := []struct {
		dataSize    int64
		verifyStart int64
		verifySize  int64
		// A byte in input data is modified during the test. If the
		// modified byte falls in verification range, Verify should
		// fail, otherwise Verify should still succeed.
		modifyByte     int64
		modifyName     bool
		modifyMode     bool
		modifyUID      bool
		modifyGID      bool
		modifyChildren bool
		shouldSucceed  bool
	}{
		// Verify range start outside the data range should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   usermem.PageSize,
			verifySize:    1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Verifying range is valid if it starts inside data and ends
		// outside data range, in that case start to the end of data is
		// verified.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Invalid verify range (negative size) should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   1,
			verifySize:    -1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// 0 verify size should only verify metadata.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			shouldSucceed: true,
		},
		// Modified name should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyName:    true,
			shouldSucceed: false,
		},
		// Modified mode should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyMode:    true,
			shouldSucceed: false,
		},
		// Modified UID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyUID:     true,
			shouldSucceed: false,
		},
		// Modified GID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyGID:     true,
			shouldSucceed: false,
		},
		// Modified Children should fail verification.
		{
			dataSize:       usermem.PageSize,
			verifyStart:    0,
			verifySize:     0,
			modifyByte:     0,
			modifyChildren: true,
			shouldSucceed:  false,
		},
		// The test cases below use a block-aligned verify range.
		// Modifying a byte in the verified range should cause verify
		// to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4 * usermem.PageSize,
			shouldSucceed: false,
		},
		// Modifying a byte before the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4*usermem.PageSize - 1,
			shouldSucceed: true,
		},
		// Modifying a byte after the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    5 * usermem.PageSize,
			shouldSucceed: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    5*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 122,
			shouldSucceed: false,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 124,
			shouldSucceed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.modifyByte), func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			// Generate random bytes in data.
			rand.Read(data)

			for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
				for _, dataAndTreeInSameFile := range []bool{false, true} {
					var tree bytesReadWriter
					genParams := GenerateParams{
						Size:                  int64(len(data)),
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						Children:              map[string]bool{},
						HashAlgorithms:        hashAlgorithms,
						TreeReader:            &tree,
						TreeWriter:            &tree,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if dataAndTreeInSameFile {
						tree.Write(data)
						genParams.File = &tree
					} else {
						genParams.File = &bytesReadWriter{
							bytes: data,
						}
					}
					hash, err := Generate(&genParams)
					if err != nil {
						t.Fatalf("Generate failed: %v", err)
					}

					// Flip a bit in data and checks Verify results.
					var buf bytes.Buffer
					data[tc.modifyByte] ^= 1
					verifyParams := VerifyParams{
						Out:                   &buf,
						File:                  bytes.NewReader(data),
						Tree:                  &tree,
						Size:                  tc.dataSize,
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						Children:              map[string]bool{},
						HashAlgorithms:        hashAlgorithms,
						ReadOffset:            tc.verifyStart,
						ReadSize:              tc.verifySize,
						Expected:              hash,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if tc.modifyName {
						verifyParams.Name = defaultName + "abc"
					}
					if tc.modifyMode {
						verifyParams.Mode = defaultMode + 1
					}
					if tc.modifyUID {
						verifyParams.UID = defaultUID + 1
					}
					if tc.modifyGID {
						verifyParams.GID = defaultGID + 1
					}
					if tc.modifyChildren {
						verifyParams.Children["abc"] = true
					}
					if tc.shouldSucceed {
						n, err := Verify(&verifyParams)
						if err != nil && err != io.EOF {
							t.Errorf("Verification failed when expected to succeed: %v", err)
						}
						if n != tc.verifySize {
							t.Errorf("Got Verify output size %d, want %d", n, tc.verifySize)
						}
						if int64(buf.Len()) != tc.verifySize {
							t.Errorf("Got Verify output buf size %d, want %d,", buf.Len(), tc.verifySize)
						}
						if !bytes.Equal(data[tc.verifyStart:tc.verifyStart+tc.verifySize], buf.Bytes()) {
							t.Errorf("Incorrect output buf from Verify")
						}
					} else {
						if _, err := Verify(&verifyParams); err == nil {
							t.Errorf("Verification succeeded when expected to fail")
						}
					}
				}
			}
		})
	}
}

func TestVerifyRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	// Use a random dataSize.  Minimum size 2 so that we can pick a random
	// portion from it.
	dataSize := rand.Int63n(200*usermem.PageSize) + 2
	data := make([]byte, dataSize)
	// Generate random bytes in data.
	rand.Read(data)

	for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
		for _, dataAndTreeInSameFile := range []bool{false, true} {
			var tree bytesReadWriter
			genParams := GenerateParams{
				Size:                  int64(len(data)),
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				Children:              map[string]bool{},
				HashAlgorithms:        hashAlgorithms,
				TreeReader:            &tree,
				TreeWriter:            &tree,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			if dataAndTreeInSameFile {
				tree.Write(data)
				genParams.File = &tree
			} else {
				genParams.File = &bytesReadWriter{
					bytes: data,
				}
			}
			hash, err := Generate(&genParams)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			// Pick a random portion of data.
			start := rand.Int63n(dataSize - 1)
			size := rand.Int63n(dataSize) + 1

			var buf bytes.Buffer
			verifyParams := VerifyParams{
				Out:                   &buf,
				File:                  bytes.NewReader(data),
				Tree:                  &tree,
				Size:                  dataSize,
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				Children:              map[string]bool{},
				HashAlgorithms:        hashAlgorithms,
				ReadOffset:            start,
				ReadSize:              size,
				Expected:              hash,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			// Checks that the random portion of data from the original data is
			// verified successfully.
			n, err := Verify(&verifyParams)
			if err != nil && err != io.EOF {
				t.Errorf("Verification failed for correct data: %v", err)
			}
			if size > dataSize-start {
				size = dataSize - start
			}
			if n != size {
				t.Errorf("Got Verify output size %d, want %d", n, size)
			}
			if int64(buf.Len()) != size {
				t.Errorf("Got Verify output buf size %d, want %d", buf.Len(), size)
			}
			if !bytes.Equal(data[start:start+size], buf.Bytes()) {
				t.Errorf("Incorrect output buf from Verify")
			}

			// Verify that modified metadata should fail verification.
			buf.Reset()
			verifyParams.Name = defaultName + "abc"
			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verify succeeded for modified metadata, expect failure")
			}

			// Flip a random bit in randPortion, and check that verification fails.
			buf.Reset()
			randBytePos := rand.Int63n(size)
			data[start+randBytePos] ^= 1
			verifyParams.File = bytes.NewReader(data)
			verifyParams.Name = defaultName

			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verification succeeded for modified data, expect failure")
			}
		}
	}
}
