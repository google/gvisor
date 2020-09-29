// Copyright 2019 The gVisor Authors.
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

// Package reviver scans the code looking for TODOs and pass them to registered
// Buggers to ensure TODOs point to active issues.
package reviver

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// regexTodo matches a TODO or FIXME comment.
var regexTodo = regexp.MustCompile(`(\/\/|#)\s*(TODO|FIXME)\(([a-zA-Z0-9.\/]+)\):\s*(.+)`)

// Bugger interface is called for every TODO found in the code. If it can handle
// the TODO, it must return true. If it returns false, the next Bugger is
// called. If no Bugger handles the TODO, it's dropped on the floor.
type Bugger interface {
	Activate(todo *Todo) (bool, error)
}

// Location saves the location where the TODO was found.
type Location struct {
	Comment string
	File    string
	Line    uint
}

// Todo represents a unique TODO. There can be several TODOs pointing to the
// same issue in the code. They are all grouped together.
type Todo struct {
	Issue     string
	Locations []Location
}

// Reviver scans the given paths for TODOs and calls Buggers to handle them.
type Reviver struct {
	paths   []string
	buggers []Bugger

	mu    sync.Mutex
	todos map[string]*Todo
	errs  []error
}

// New create a new Reviver.
func New(paths []string, buggers []Bugger) *Reviver {
	return &Reviver{
		paths:   paths,
		buggers: buggers,
		todos:   map[string]*Todo{},
	}
}

// Run runs. It returns all errors found during processing, it doesn't stop
// on errors.
func (r *Reviver) Run() []error {
	// Process each directory in parallel.
	wg := sync.WaitGroup{}
	for _, path := range r.paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			r.processPath(path, &wg)
		}(path)
	}

	wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Printf("Processing %d TODOs (%d errors)...\n", len(r.todos), len(r.errs))
	dropped := 0
	for _, todo := range r.todos {
		ok, err := r.processTodo(todo)
		if err != nil {
			r.errs = append(r.errs, err)
		}
		if !ok {
			dropped++
		}
	}
	fmt.Printf("Processed %d TODOs, %d were skipped (%d errors)\n", len(r.todos)-dropped, dropped, len(r.errs))

	return r.errs
}

func (r *Reviver) processPath(path string, wg *sync.WaitGroup) {
	fmt.Printf("Processing dir %q\n", path)
	fis, err := ioutil.ReadDir(path)
	if err != nil {
		r.addErr(fmt.Errorf("error processing dir %q: %v", path, err))
		return
	}

	for _, fi := range fis {
		childPath := filepath.Join(path, fi.Name())
		switch {
		case fi.Mode().IsDir():
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.processPath(childPath, wg)
			}()

		case fi.Mode().IsRegular():
			file, err := os.Open(childPath)
			if err != nil {
				r.addErr(err)
				continue
			}

			scanner := bufio.NewScanner(file)
			lineno := uint(0)
			for scanner.Scan() {
				lineno++
				line := scanner.Text()
				if todo := r.processLine(line, childPath, lineno); todo != nil {
					r.addTodo(todo)
				}
			}
		}
	}
}

func (r *Reviver) processLine(line, path string, lineno uint) *Todo {
	matches := regexTodo.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}
	if len(matches) != 5 {
		panic(fmt.Sprintf("regex returned wrong matches for %q: %v", line, matches))
	}
	return &Todo{
		Issue: matches[3],
		Locations: []Location{
			{
				File:    path,
				Line:    lineno,
				Comment: matches[4],
			},
		},
	}
}

func (r *Reviver) addTodo(newTodo *Todo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if todo := r.todos[newTodo.Issue]; todo == nil {
		r.todos[newTodo.Issue] = newTodo
	} else {
		todo.Locations = append(todo.Locations, newTodo.Locations...)
	}
}

func (r *Reviver) addErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *Reviver) processTodo(todo *Todo) (bool, error) {
	for _, bugger := range r.buggers {
		ok, err := bugger.Activate(todo)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
