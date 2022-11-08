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

// Binary yamltest does strict yaml parsing and validation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xeipuuv/gojsonschema"
	yaml "gopkg.in/yaml.v2"
)

var (
	schema = flag.String("schema", "", "path to JSON schema file.")
	strict = flag.Bool("strict", true, "Whether to enable strict mode for YAML decoding")
)

func fixup(v any) (any, error) {
	switch x := v.(type) {
	case map[any]any:
		// Coerse into a string-based map, required for yaml.
		strMap := make(map[string]any)
		for k, v := range x {
			strK, ok := k.(string)
			if !ok {
				// This cannot be converted to JSON at all.
				return nil, fmt.Errorf("invalid key %T in (%#v)", k, x)
			}
			fv, err := fixup(v)
			if err != nil {
				return nil, fmt.Errorf(".%s%w", strK, err)
			}
			strMap[strK] = fv
		}
		return strMap, nil
	case []any:
		for i := range x {
			fv, err := fixup(x[i])
			if err != nil {
				return nil, fmt.Errorf("[%d]%w", i, err)
			}
			x[i] = fv
		}
		return x, nil
	default:
		return v, nil
	}
}

func loadFile(filename string) (gojsonschema.JSONLoader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.SetStrict(*strict)
	var object any
	if err := dec.Decode(&object); err != nil {
		return nil, err
	}
	fixedObject, err := fixup(object) // For serialization.
	if err != nil {
		return nil, err
	}
	bytes, err := json.Marshal(fixedObject)
	if err != nil {
		return nil, err
	}
	return gojsonschema.NewStringLoader(string(bytes)), nil
}

func main() {
	flag.Parse()
	if *schema == "" || len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// Construct our schema loader.
	schemaLoader := gojsonschema.NewReferenceLoader(fmt.Sprintf("file://%s", *schema))

	// Parse all documents.
	allErrors := make(map[string][]error)
	for _, filename := range flag.Args() {
		// Record the filename with an empty slice for below, where
		// we will emit all files (even those without any errors).
		allErrors[filename] = nil
		documentLoader, err := loadFile(filename)
		if err != nil {
			allErrors[filename] = append(allErrors[filename], err)
			continue
		}
		result, err := gojsonschema.Validate(schemaLoader, documentLoader)
		if err != nil {
			allErrors[filename] = append(allErrors[filename], err)
			continue
		}
		for _, desc := range result.Errors() {
			allErrors[filename] = append(allErrors[filename], errors.New(desc.String()))
		}
	}

	// Print errors in yaml format.
	totalErrors := 0
	for filename, errs := range allErrors {
		totalErrors += len(errs)
		if len(errs) == 0 {
			fmt.Fprintf(os.Stderr, "%s: ✓\n", filename)
			continue
		}
		fmt.Fprintf(os.Stderr, "%s:\n", filename)
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "- %s\n", err)
		}
	}
	if totalErrors != 0 {
		os.Exit(1)
	}
}
