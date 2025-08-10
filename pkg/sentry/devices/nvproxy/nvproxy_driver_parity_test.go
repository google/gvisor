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
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/test/testutil"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/tools/gpu/drivers"
	"gvisor.dev/gvisor/tools/nvidia_driver_differ/parser"
)

func createParserRunner(t *testing.T) *parser.Runner {
	t.Helper()

	// Find the parser binary
	parserPath, err := testutil.FindFile("tools/nvidia_driver_differ/driver_ast_parser")
	if err != nil {
		t.Fatalf("Failed to find driver_ast_parser: %v", err)
	}

	runner, err := parser.NewRunner(parserPath)
	if err != nil {
		t.Fatalf("Failed to create parser runner: %v", err)
	}

	return runner
}

func getDriverDefs(t *testing.T, runner *parser.Runner, version nvconf.DriverVersion) (*nvproxy.DriverABIInfo, *parser.OutputJSON) {
	t.Helper()

	info, ok := nvproxy.SupportedIoctls(version)
	if !ok {
		t.Fatalf("failed to get struct names for driver %q", version.String())
	}

	// Create structs file for parser
	if err := runner.CreateInputFile(info); err != nil {
		t.Fatalf("failed to create temporary structs list: %v", err)
	}

	// Run parser
	defs, err := runner.ParseDriver(version)
	if err != nil {
		t.Fatalf("failed to run driver_ast_parser: %v", err)
	}

	return info, defs
}

// TestStructDefinitionParity tests that the struct definitions in nvproxy are the same as the
// definitions in the driver source code.
func TestStructDefinitionParity(t *testing.T) {
	nvproxy.Init()

	nvproxy.ForEachSupportDriver(func(version nvconf.DriverVersion, _ nvproxy.Checksums) {
		t.Run(version.String(), func(t *testing.T) {
			t.Parallel()
			runner := createParserRunner(t)

			nvproxyIoctls, defs := getDriverDefs(t, runner, version)

			checkIoctl := func(ioctlNum uint32, nvproxyIoctl nvproxy.IoctlInfo) {
				if nvproxyIoctl.Name == "" {
					return
				}
				// Check if the ioctl number has changed.
				if driverIoctlNum, ok := defs.Constants[nvproxyIoctl.Name]; !ok {
					t.Errorf("ioctl %q not found in driver source code", nvproxyIoctl.Name)
				} else if driverIoctlNum != uint64(ioctlNum) {
					t.Errorf("ioctl %q has changed numbers between nvproxy (%#x) and driver (%#x)",
						nvproxyIoctl.Name, ioctlNum, defs.Constants[nvproxyIoctl.Name])
				}

				for _, nvproxyDef := range nvproxyIoctl.Structs {
					// Check if the nvproxy definition has disallowed types.
					if nvproxyDef.Type != nil {
						fields := flattenNvproxyStruct(t, nvproxyDef.Type)
						for _, field := range fields {
							if _, ok := typeAllowlist[field.Type.Kind()]; !ok {
								t.Errorf("struct %q has disallowed type %q in nvproxy", nvproxyDef.Name, field.Type.Name())
							}
						}
					}

					// Compare the nvproxy definition to the parser output.
					name := nvproxyDef.Name
					_, isRecord := defs.Records[name]
					aliasDef, isAlias := defs.Aliases[name]
					if !isRecord && !isAlias {
						t.Errorf("struct %q not found in parser output for version %q", name, version.String())
						continue
					}

					switch {
					case isRecord && nvproxyDef.Type == nil:
						checkSimpleRecord(t, name, defs)
					case isRecord && nvproxyDef.Type != nil:
						if err := compareStructs(t, nvproxyDef.Type, name, defs); err != nil {
							t.Errorf("struct %q has different definitions between nvproxy and driver: %v", name, err)
						}
					case isAlias && nvproxyDef.Type == nil:
						// For now, there is no good way to check if an alias is still simple.
						// Regardless, none of the current ioctls fall into this category.
						t.Errorf("struct %q is a simple alias, which is not supported yet", name)
					case isAlias && nvproxyDef.Type != nil:
						checkComplexAlias(t, nvproxyDef, aliasDef)
					}
				}
			}
			for num, info := range nvproxyIoctls.FrontendInfos {
				checkIoctl(num, info)
			}
			for num, info := range nvproxyIoctls.ControlInfos {
				checkIoctl(num, info)
			}
			for num, info := range nvproxyIoctls.AllocationInfos {
				checkIoctl(uint32(num), info)
			}
			for num, info := range nvproxyIoctls.UvmInfos {
				checkIoctl(num, info)
			}
		})
	})
}

// checkSimpleRecord checks that a record is still a simple ioctl.
func checkSimpleRecord(t *testing.T, name string, output *parser.OutputJSON) {
	t.Helper()

	// This is a simple ioctl, so we want to see if it's still simple
	// This means seeing if a field is NvP64, or if a field name ends in "fd"
	driverFields := flattenDriverStruct(t, name, output)
	for _, field := range driverFields {
		if field.Type == "NvP64" {
			t.Errorf("struct %q is a simple ioctl in nvproxy, but field %q has type NvP64 in the driver", name, field.Name)
		}
		if strings.HasSuffix(strings.ToLower(field.Name), "fd") {
			t.Errorf("struct %q is a simple ioctl in nvproxy, but field %q ends in \"fd\" in the driver", name, field.Name)
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
		t.Errorf("struct %q has different sizes between nvproxy (%d) and driver (%d) (bytes)",
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

// typeAllowlist is a set of types that are allowed on the nvproxy side.
var typeAllowlist = map[reflect.Kind]struct{}{
	reflect.Int8:   {},
	reflect.Uint8:  {},
	reflect.Int16:  {},
	reflect.Uint16: {},
	reflect.Int32:  {},
	reflect.Uint32: {},
	reflect.Int64:  {},
	reflect.Uint64: {},
	reflect.Array:  {},
	reflect.Struct: {},
}

func isDriverBaseType(t string) bool {
	_, ok := typeMap[t]
	return ok
}

func isNvproxyBaseType(t reflect.Type) bool {
	for _, baseType := range typeMap {
		if t == baseType {
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
			continue
		}

		// This is a nested struct, so we flatten the field.
		nestedFields := flattenNvproxyStruct(t, field.Type)

		// Update offset of each nested field to be relative to the parent struct.
		for i := range nestedFields {
			nestedFields[i].Offset += field.Offset
		}
		fields = append(fields, nestedFields...)
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
		return fmt.Errorf("mismatched sizes for struct %q between nvproxy (%d) and driver (%d) (bytes)",
			driverStructName, nvproxyStruct.Size(), driverStructDef.Size)
	}

	// Flatten structs so we don't have to worry about nested structs.
	nvproxyFields := flattenNvproxyStruct(t, nvproxyStruct)
	driverFields := flattenDriverStruct(t, driverStructName, output)

	// We loop through both definitions with two pointers. We only increment the driver pointer
	// when we find a field in the nvproxy struct with the same offset, at which point we compare
	// the types.
	driverFieldNum := 0
	for _, nvproxyField := range nvproxyFields {
		// We get this case if there are padding fields at the very end of the nvproxy struct.
		// Since we check the size above, we can just ignore these fields.
		if driverFieldNum == len(driverFields) {
			break
		}

		driverField := driverFields[driverFieldNum]
		if uint64(nvproxyField.Offset) == driverField.Offset {
			if err := compareTypes(t, nvproxyField.Type, driverField.Type, output); err != nil {
				return fmt.Errorf("mismatched field types for struct %q between nvproxy field %q and driver field %q: %w"+
					"\n nvproxy fields: %v\n driver fields: %v",
					driverStructName, nvproxyField.Name, driverField.Name, err,
					nvproxyFields, driverFields)
			}
			driverFieldNum++
		}
	}

	// If we have not reached the end of the driver fields, then we have not found a match for every
	// field.
	if driverFieldNum != len(driverFields) {
		return fmt.Errorf("unable to find a match for driver field %q for struct %q in nvproxy"+
			"\n nvproxy fields: %v\n driver fields: %v",
			driverFields[driverFieldNum].Name, driverStructName,
			nvproxyFields, driverFields)
	}

	return nil
}

// arrayTypeRegex matches array types in the form of "type[size]".
// To allow for nested arrays, we accept brackets in the type name.
// Types may also have colons (e.g. "struct::field_t").
var arrayTypeRegex = regexp.MustCompile(`([\w:\[\]]+)\[(\d+)\]`)

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
		// We need a special case for ClassID, which nvproxy uses for allocation classes but the driver
		// uses as a uint32.
		if nvproxyType == reflect.TypeFor[nvgpu.ClassID]() {
			nvproxyType = reflect.TypeFor[uint32]()
		}

		if nvproxyType != driverType {
			return fmt.Errorf("mismatched type between nvproxy (%q) and driver (%q)",
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
	// - Enum type should always map to uint32
	// - Struct type we compare using compareStructs
	// - Union type we compare sizes
	if isDriverBaseType(driverTypeName) {
		return compareReflectTypes(nvproxyType, typeMap[driverTypeName])
	}
	if strings.HasPrefix(driverTypeName, "enum") {
		return compareReflectTypes(nvproxyType, reflect.TypeFor[uint32]())
	}
	if recordDef, isRecord := output.Records[driverTypeName]; isRecord {
		if !recordDef.IsUnion {
			return compareStructs(t, nvproxyType, driverTypeName, output)
		}
		if uint64(nvproxyType.Size()) != recordDef.Size {
			return fmt.Errorf("mismatched union sizes between nvproxy (%d) and driver (%d)",
				nvproxyType.Size(), recordDef.Size)
		}

		return nil
	}

	t.Fatalf("unknown driver type %q", driverTypeName)
	return nil
}

// TestDriverChecksums tests that the checksums of all drivers are correct.
func TestDriverChecksums(t *testing.T) {
	ctx := context.Background()
	nvproxy.Init()
	nvproxy.ForEachSupportDriver(func(version nvconf.DriverVersion, checksums nvproxy.Checksums) {
		t.Run(version.String(), func(t *testing.T) {
			t.Parallel()
			if err := drivers.ValidateChecksum(ctx, version.String(), checksums); err != nil {
				t.Errorf("checksum mismatch for driver %q: %v", version.String(), err)
			}
		})
	})

}
