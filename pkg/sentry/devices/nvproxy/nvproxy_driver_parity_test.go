// Copyright 2024 The gVisor Authors.
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

//go:build !false
// +build !false

// Package nvproxy_driver_parity_test tests that the nvproxy driver ABI
// is kept up to date with the NVIDIA driver.
package nvproxy_driver_parity_test

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/test/testutil"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/tools/nvidia_driver_differ/parser"
)

func createParserRunner(t *testing.T) (*os.File, *parser.Runner) {
	t.Helper()

	// Find the parser binary
	parserPath, err := testutil.FindFile("tools/nvidia_driver_differ/driver_ast_parser")
	if err != nil {
		t.Fatalf("Failed to find driver_ast_parser: %v", err)
	}
	parserFile, err := os.Open(parserPath)
	if err != nil {
		t.Fatalf("Failed to open driver_ast_parser: %v", err)
	}

	runner, err := parser.NewRunner((*parser.ParserFile)(parserFile))
	if err != nil {
		t.Fatalf("Failed to create parser runner: %v", err)
	}

	return parserFile, runner
}

func getDriverDefs(t *testing.T, runner *parser.Runner, version nvproxy.DriverVersion) ([]nvproxy.DriverStructName, *parser.OutputJSON) {
	t.Helper()

	structNames, ok := nvproxy.SupportedStructNames(version)
	if !ok {
		t.Fatalf("failed to get struct names for driver %q", version.String())
	}

	// Create structs file for parser
	if err := runner.CreateStructsFile(structNames); err != nil {
		t.Fatalf("failed to create temporary structs list: %v", err)
	}

	// Run parser
	defs, err := runner.ParseDriver(version)
	if err != nil {
		t.Fatalf("failed to run driver_ast_parser: %v", err)
	}

	return structNames, defs
}

// TestSupportedStructNames tests that all the structs listed in nvproxy are found in the driver
// source code.
func TestSupportedStructNames(t *testing.T) {
	f, runner := createParserRunner(t)
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close driver_ast_parser: %v", err)
		}
	}()
	nvproxy.Init()

	// Run the parser on all supported driver versions
	nvproxy.ForEachSupportDriver(func(version nvproxy.DriverVersion, checksum string) {
		t.Run(version.String(), func(t *testing.T) {
			structNames, defs := getDriverDefs(t, runner, version)

			// Check that every struct is found in the parser output.
			for _, name := range structNames {
				_, isRecord := defs.Records[string(name)]
				_, isAlias := defs.Aliases[string(name)]
				if !isRecord && !isAlias {
					t.Errorf("struct %q not found in parser output for version %q", name, version.String())
				}
			}
		})
	})
}

func TestStructDefinitionParity(t *testing.T) {
	f, runner := createParserRunner(t)
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close driver_ast_parser: %v", err)
		}
	}()
	nvproxy.Init()

	nvproxy.ForEachSupportDriver(func(version nvproxy.DriverVersion, checksum string) {
		t.Run(version.String(), func(t *testing.T) {
			_, defs := getDriverDefs(t, runner, version)

			nvproxyDefs, ok := nvproxy.SupportedStructTypes(version)
			if !ok {
				t.Fatalf("failed to get struct instances for driver %q", version.String())
			}

			for _, nvproxyDef := range nvproxyDefs {
				name := nvproxyDef.Name
				recordDef, isRecord := defs.Records[name]
				aliasDef, isAlias := defs.Aliases[name]
				if !isRecord && !isAlias {
					t.Errorf("struct %q not found in parser output for version %q", name, version.String())
					continue
				}

				switch {
				case isRecord && nvproxyDef.Type == nil:
					checkSimpleRecord(t, name, recordDef)
				case isRecord && nvproxyDef.Type != nil:
					if err := compareStructs(t, nvproxyDef.Type, name, defs); err != nil {
						t.Errorf("struct %q has different definitions between nvproxy and driver: %v", name, err)
					}
				case isAlias && nvproxyDef.Type == nil:
					// For now, there is no good way to check if an alias is still simple.
					// Regardless, none of the current ioctls fall into this category.
				case isAlias && nvproxyDef.Type != nil:
					checkComplexAlias(t, nvproxyDef, aliasDef)
				}
			}
		})
	})
}

// checkSimpleRecord checks that a record is still a simple ioctl.
func checkSimpleRecord(t *testing.T, name string, recordDef parser.RecordDef) {
	t.Helper()

	// This is a simple ioctl, so we want to see if it's still simple
	// This means seeing if a field is NvP64, or if a field name ends in "fd"
	for _, field := range recordDef.Fields {
		if field.Type == "NvP64" || strings.HasSuffix(field.Name, "fd") {
			t.Errorf("struct %q is no longer a simple ioctl", name)
			return
		}
	}
}

// checkComplexAlias checks that the nvproxy struct definition is still compatible
// with the driver alias definition. This only applies to a very small set of cases where
// the type is a struct in nvproxy but an alias in the driver (e.g. NvHandle).
func checkComplexAlias(t *testing.T, nvproxyDef nvproxy.DriverStruct, aliasDef parser.TypeDef) {
	t.Helper()

	// To compare a struct against an alias, we compare the sizes.
	nvproxySize := uint64(nvproxyDef.Type.Size())
	driverSize := aliasDef.Size
	if nvproxySize != driverSize {
		t.Errorf("struct %q has different sizes between nvproxy (%d) and driver (%d)",
			nvproxyDef.Name, nvproxySize, driverSize)
	}
}

// typeMap maps the base types defined in the driver to their corresponding reflect.Type.
var typeMap = map[string]reflect.Type{
	"NvP64":              reflect.TypeFor[nvgpu.P64](),
	"NvHandle":           reflect.TypeFor[nvgpu.Handle](),
	"NvProcessorUuid":    reflect.TypeFor[nvgpu.NvUUID](),
	"char":               reflect.TypeFor[byte](),
	"unsigned char":      reflect.TypeFor[uint8](),
	"short":              reflect.TypeFor[int16](),
	"unsigned short":     reflect.TypeFor[uint16](),
	"int":                reflect.TypeFor[int32](),
	"unsigned int":       reflect.TypeFor[uint32](),
	"long long":          reflect.TypeFor[int64](),
	"unsigned long long": reflect.TypeFor[uint64](),
}

func isDriverBaseType(t string) bool {
	_, ok := typeMap[t]
	return ok
}

func isNvproxyBaseType(t reflect.Type) bool {
	for _, baseType := range typeMap {
		if t.ConvertibleTo(baseType) {
			return true
		}
	}
	return false
}

// flattenNvproxyStruct flattens a nvproxy struct by recursively flattening any nested structs.
func flattenNvproxyStruct(t *testing.T, structType reflect.Type) []reflect.StructField {
	t.Helper()

	if structType.Kind() != reflect.Struct {
		t.Fatalf("nvproxy struct %q is not a struct", structType.Name())
	}

	var fields []reflect.StructField
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		// Check if the field is any base type defined in typeMap.
		// This avoids flattening the fields of a struct that is a base type.
		if field.Type.Kind() != reflect.Struct || isNvproxyBaseType(field.Type) {
			fields = append(fields, field)
		} else {
			// This is a nested struct, so we flatten the field.
			nestedFields := flattenNvproxyStruct(t, field.Type)

			// Update offset of each nested field to be relative to the parent struct.
			for i := range nestedFields {
				nestedFields[i].Offset += field.Offset
			}
			fields = append(fields, nestedFields...)
		}
	}
	return fields
}

// flattenDriverStruct flattens a driver struct by recursively flattening any nested structs.
func flattenDriverStruct(t *testing.T, structName string, output *parser.OutputJSON) []parser.RecordField {
	t.Helper()

	structDef, ok := output.Records[structName]
	if !ok {
		t.Fatalf("driver struct %q not found in parser output", structName)
	}

	var fields []parser.RecordField
	for _, field := range structDef.Fields {
		// Check if the field is any base type defined in typeMap.
		// This avoids flattening the fields of a struct that is a base type.
		if isDriverBaseType(field.Type) {
			fields = append(fields, field)
			continue
		}

		if fieldDef, isRecord := output.Records[field.Type]; isRecord && !fieldDef.IsUnion {
			nestedFields := flattenDriverStruct(t, field.Type, output)

			// Update offset of each nested field to be relative to the parent struct.
			for i := range nestedFields {
				nestedFields[i].Offset += field.Offset
			}
			fields = append(fields, nestedFields...)
		} else {
			fields = append(fields, field)
		}
	}
	return fields
}

// compareStructs compares the definition of a struct in nvproxy to its definition in the driver.
// It checks that the size and field types are the same, and returns an error if they are not.
func compareStructs(t *testing.T, nvproxyStruct reflect.Type, driverStructName string, output *parser.OutputJSON) error {
	t.Helper()

	driverStructDef, ok := output.Records[driverStructName]
	if !ok {
		t.Fatalf("driver struct %q not found in parser output", driverStructName)
	}

	if uint64(nvproxyStruct.Size()) != driverStructDef.Size {
		return fmt.Errorf("mismatched struct sizes between nvproxy (%d) and driver (%d)",
			nvproxyStruct.Size(), driverStructDef.Size)
	}

	// Flatten structs so we don't have to worry about nested structs.
	nvproxyFields := flattenNvproxyStruct(t, nvproxyStruct)
	driverFields := flattenDriverStruct(t, driverStructName, output)

	// Filter out nvproxy fields that do not have a matching offset with a field in the driver struct.
	// This is should remove all padding fields.
	var filteredNvproxyFields []reflect.StructField
	for i, j := 0, 0; i < len(nvproxyFields) && j < len(driverFields); i++ {
		if uint64(nvproxyFields[i].Offset) == driverFields[j].Offset {
			filteredNvproxyFields = append(filteredNvproxyFields, nvproxyFields[i])
			j++
		}
	}

	// After filtering, we should have the same number of fields in both structs.
	if len(filteredNvproxyFields) != len(driverFields) {
		return fmt.Errorf("mismatched number of fields between nvproxy (%d) and driver (%d)",
			len(filteredNvproxyFields), len(driverFields))
	}

	// Check equality between each field type.
	for i := 0; i < len(filteredNvproxyFields); i++ {
		nvproxyField := filteredNvproxyFields[i]
		driverField := driverFields[i]

		if err := compareTypes(t, nvproxyField.Type, driverField.Type, output); err != nil {
			return fmt.Errorf("mismatched field types between nvproxy (%q) and driver (%q): %w",
				nvproxyField.Name, driverField.Type, err)
		}
	}

	return nil
}

// arrayTypeRegex matches array types in the form of "type[size]".
var arrayTypeRegex = regexp.MustCompile(`(.+)\[(\d+)\]`)

// compareTypes compares the type of a field in nvproxy to its type in the driver, returning an
// error if they are not.
func compareTypes(t *testing.T, nvproxyType reflect.Type, driverTypeName string, output *parser.OutputJSON) error {
	t.Helper()

	// Check if we have array type
	if matches := arrayTypeRegex.FindStringSubmatch(driverTypeName); matches != nil {
		// Get the base type name and array size
		if len(matches) != 3 {
			t.Fatalf("failed to parse array type %q", driverTypeName)
		}
		baseTypeName := matches[1]
		arraySize, err := strconv.Atoi(matches[2])
		if err != nil {
			t.Fatalf("failed to parse array size %q", matches[2])
		}

		// Compare size and base type of the arrays
		if nvproxyType.Kind() != reflect.Array || nvproxyType.Len() != arraySize {
			return fmt.Errorf("mismatched array size between nvproxy (%d) and driver (%d)",
				nvproxyType.Len(), arraySize)
		}
		return compareTypes(t, nvproxyType.Elem(), baseTypeName, output)
	}

	compareReflectTypes := func(nvproxyType, driverType reflect.Type) error {
		if !nvproxyType.ConvertibleTo(driverType) {
			return fmt.Errorf("cannot convert nvproxy type %q to driver type %q",
				nvproxyType.Name(), driverType.Name())
		}
		return nil
	}

	// First check if the field is any base type defined in typeMap.
	// This avoids simplifying types like NvP64 which we have special nvproxy types for.
	if isDriverBaseType(driverTypeName) {
		return compareReflectTypes(nvproxyType, typeMap[driverTypeName])
	}

	// If the field is not a base type, try and work with its alias to
	// simplify the comparison.
	if typeAlias, ok := output.Aliases[driverTypeName]; ok {
		driverTypeName = typeAlias.Type
	}

	// We have the following cases to compare:
	// - Base type is given by typeMap
	// - Enum type should always goes to uint32
	// - Struct type we compare using CompareStructs
	// - Union type we compare sizes
	if isDriverBaseType(driverTypeName) {
		return compareReflectTypes(nvproxyType, typeMap[driverTypeName])
	} else if strings.HasPrefix(driverTypeName, "enum") {
		return compareReflectTypes(nvproxyType, reflect.TypeFor[uint32]())
	} else if recordDef, isRecord := output.Records[driverTypeName]; isRecord {
		if !recordDef.IsUnion {
			return compareStructs(t, nvproxyType, driverTypeName, output)
		} else if uint64(nvproxyType.Size()) != recordDef.Size {
			return fmt.Errorf("mismatched union sizes between nvproxy (%d) and driver (%d)",
				nvproxyType.Size(), recordDef.Size)
		}

		return nil
	}

	t.Fatalf("unknown driver type %q", driverTypeName)
	return nil
}
