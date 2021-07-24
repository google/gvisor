// Copyright 2021 The gVisor Authors.
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

package bitmap

import (
	"math"
	"reflect"
	"testing"
)

// generateFilledSlice generates a slice fill with numbers.
func generateFilledSlice(min, max, length int) []uint32 {
	if max == min {
		return []uint32{uint32(min)}
	}
	if length > (max - min) {
		return nil
	}
	randSlice := make([]uint32, length)
	if length != 0 {
		rangeNum := uint32((max - min) / length)
		randSlice[0], randSlice[length-1] = uint32(min), uint32(max)
		for i := 1; i < length-1; i++ {
			randSlice[i] = randSlice[i-1] + rangeNum
		}
	}
	return randSlice
}

// generateFilledBitmap generates a Bitmap filled with fillNum of numbers,
// and returns the slice and bitmap.
func generateFilledBitmap(min, max, fillNum int) ([]uint32, Bitmap) {
	bitmap := BitmapWithSize(uint32(max))
	randSlice := generateFilledSlice(min, max, fillNum)
	for i := 0; i < fillNum; i++ {
		bitmap.Add(randSlice[i])
	}
	return randSlice, bitmap
}

func TestNewBitmap(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		expectSize int
	}{
		{"length 1", 1, 1},
		{"length 1024", 1024, 16},
		{"length 1025", 1025, 17},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if bitmap := BitmapWithSize(uint32(tt.size)); len(bitmap.bitBlock) != tt.expectSize {
				t.Errorf("BitmapWithSize created bitmap with %v, bitBlock size: %d, wanted: %d", tt.name, len(bitmap.bitBlock), tt.expectSize)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name       string
		bitmapSize int
		addNum     int
	}{
		{"Add with null bitmap.bitBlock", 0, 10},
		{"Add without extending bitBlock", 64, 10},
		{"Add without extending bitblock with margin number", 63, 64},
		{"Add with extended one block", 1024, 1025},
		{"Add with extended more then one block", 1024, 2048},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bitmap := BitmapWithSize(uint32(tt.bitmapSize))
			bitmap.Add(uint32(tt.addNum))
			bitmapSlice := bitmap.ToSlice()
			if bitmapSlice[0] != uint32(tt.addNum) {
				t.Errorf("%v, get number: %d, wanted: %d.", tt.name, bitmapSlice[0], tt.addNum)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	bitmap := BitmapWithSize(uint32(1024))
	firstSlice := generateFilledSlice(0, 511, 50)
	secondSlice := generateFilledSlice(512, 1024, 50)
	for i := 0; i < 50; i++ {
		bitmap.Add(firstSlice[i])
		bitmap.Add(secondSlice[i])
	}

	for i := 0; i < 50; i++ {
		bitmap.Remove(firstSlice[i])
	}
	bitmapSlice := bitmap.ToSlice()
	if !reflect.DeepEqual(bitmapSlice, secondSlice) {
		t.Errorf("After Remove() firstSlice, remained slice: %v, wanted: %v", bitmapSlice, secondSlice)
	}

	for i := 0; i < 50; i++ {
		bitmap.Remove(secondSlice[i])
	}
	bitmapSlice = bitmap.ToSlice()
	emptySlice := make([]uint32, 0)
	if !reflect.DeepEqual(bitmapSlice, emptySlice) {
		t.Errorf("After Remove secondSlice, remained slice: %v, wanted: %v", bitmapSlice, emptySlice)
	}

}

// Verify flip bits within one bitBlock, one bit and bits cross multi bitBlocks.
func TestFlipRange(t *testing.T) {
	tests := []struct {
		name           string
		flipRangeMin   int
		flipRangeMax   int
		filledSliceLen int
	}{
		{"Flip one number in bitmap", 77, 77, 1},
		{"Flip numbers within one bitBlocks", 5, 60, 20},
		{"Flip numbers that cross multi bitBlocks", 20, 1000, 300},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fillSlice, bitmap := generateFilledBitmap(tt.flipRangeMin, tt.flipRangeMax, tt.filledSliceLen)
			flipFillSlice := make([]uint32, 0)
			for i, j := tt.flipRangeMin, 0; i <= tt.flipRangeMax; i++ {
				if uint32(i) != fillSlice[j] {
					flipFillSlice = append(flipFillSlice, uint32(i))
				} else {
					j++
				}
			}

			bitmap.FlipRange(uint32(tt.flipRangeMin), uint32(tt.flipRangeMax+1))
			flipBitmapSlice := bitmap.ToSlice()
			if !reflect.DeepEqual(flipFillSlice, flipBitmapSlice) {
				t.Errorf("%v, flipped slice: %v, wanted: %v", tt.name, flipBitmapSlice, flipFillSlice)
			}
		})
	}
}

// Verify clear bits within one bitBlock, one bit and bits cross multi bitBlocks.
func TestClearRange(t *testing.T) {
	tests := []struct {
		name          string
		clearRangeMin int
		clearRangeMax int
		bitmapSize    int
	}{
		{"ClearRange clear one number", 5, 5, 64},
		{"ClearRange clear numbers within one bitBlock", 4, 61, 64},
		{"ClearRange clear numbers cross multi bitBlocks", 20, 254, 512},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bitmap := BitmapWithSize(uint32(tt.bitmapSize))
			bitmap.FlipRange(uint32(0), uint32(tt.bitmapSize))
			bitmap.ClearRange(uint32(tt.clearRangeMin), uint32(tt.clearRangeMax+1))
			clearedBitmapSlice := bitmap.ToSlice()
			clearedSlice := make([]uint32, 0)
			for i := 0; i < tt.bitmapSize; i++ {
				if i < tt.clearRangeMin || i > tt.clearRangeMax {
					clearedSlice = append(clearedSlice, uint32(i))
				}
			}
			if !reflect.DeepEqual(clearedSlice, clearedBitmapSlice) {
				t.Errorf("%v, cleared slice: %v, wanted: %v", tt.name, clearedBitmapSlice, clearedSlice)
			}
		})

	}
}

func TestMinimum(t *testing.T) {
	randSlice, bitmap := generateFilledBitmap(0, 1024, 200)
	min := bitmap.Minimum()
	if min != randSlice[0] {
		t.Errorf("Minimum() returns: %v, wanted: %v", min, randSlice[0])
	}

	bitmap.ClearRange(uint32(0), uint32(200))
	min = bitmap.Minimum()
	bitmapSlice := bitmap.ToSlice()
	if min != bitmapSlice[0] {
		t.Errorf("After ClearRange, Minimum() returns: %v, wanted: %v", min, bitmapSlice[0])
	}

	bitmap.FlipRange(uint32(2), uint32(11))
	min = bitmap.Minimum()
	bitmapSlice = bitmap.ToSlice()
	if min != bitmapSlice[0] {
		t.Errorf("After Flip, Minimum() returns: %v, wanted: %v", min, bitmapSlice[0])
	}
}

func TestMaximum(t *testing.T) {
	randSlice, bitmap := generateFilledBitmap(0, 1024, 200)
	max := bitmap.Maximum()
	if max != randSlice[len(randSlice)-1] {
		t.Errorf("Maximum() returns: %v, wanted: %v", max, randSlice[len(randSlice)-1])
	}

	bitmap.ClearRange(uint32(1000), uint32(1025))
	max = bitmap.Maximum()
	bitmapSlice := bitmap.ToSlice()
	if max != bitmapSlice[len(bitmapSlice)-1] {
		t.Errorf("After ClearRange, Maximum() returns: %v, wanted: %v", max, bitmapSlice[len(bitmapSlice)-1])
	}

	bitmap.FlipRange(uint32(1001), uint32(1021))
	max = bitmap.Maximum()
	bitmapSlice = bitmap.ToSlice()
	if max != bitmapSlice[len(bitmapSlice)-1] {
		t.Errorf("After Flip, Maximum() returns: %v, wanted: %v", max, bitmapSlice[len(bitmapSlice)-1])
	}
}

func TestBitmapNumOnes(t *testing.T) {
	randSlice, bitmap := generateFilledBitmap(0, 1024, 200)
	bitmapOnes := bitmap.GetNumOnes()
	if bitmapOnes != uint32(200) {
		t.Errorf("GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 200)
	}
	// Remove 10 numbers.
	for i := 5; i < 15; i++ {
		bitmap.Remove(randSlice[i])
	}
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(190) {
		t.Errorf("After Remove 10 number, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 190)
	}
	// Remove the 10 number again, the length supposed not change.
	for i := 5; i < 15; i++ {
		bitmap.Remove(randSlice[i])
	}
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(190) {
		t.Errorf("After Remove the 10 number again, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 190)
	}

	// Add 10 number.
	for i := 1080; i < 1090; i++ {
		bitmap.Add(uint32(i))
	}
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(200) {
		t.Errorf("After Add 10 number, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 200)
	}

	// Add the 10 number again, the length supposed not change.
	for i := 1080; i < 1090; i++ {
		bitmap.Add(uint32(i))
	}
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(200) {
		t.Errorf("After Add the 10 number again, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 200)
	}

	// Flip 10 bits from 0 to 1.
	bitmap.FlipRange(uint32(1025), uint32(1035))
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(210) {
		t.Errorf("After Flip, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 210)
	}

	// ClearRange numbers range from [0, 1025).
	bitmap.ClearRange(uint32(0), uint32(1025))
	bitmapOnes = bitmap.GetNumOnes()
	if bitmapOnes != uint32(20) {
		t.Errorf("After ClearRange, GetNumOnes() returns: %v, wanted: %v", bitmapOnes, 20)
	}
}

func TestFirstZero(t *testing.T) {
	bitmap := BitmapWithSize(uint32(1000))
	bitmap.FlipRange(200, 400)
	for i, j := range map[uint32]uint32{0: 0, 201: 400, 200: 400, 199: 199, 400: 400, 10000: math.MaxInt32} {
		v := bitmap.FirstZero(i)
		if v != j {
			t.Errorf("Minimum() returns: %v, wanted: %v", v, j)
		}
	}
}
