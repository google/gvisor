// Copyright 2018 Google Inc.
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

// Package urpc provides a minimal RPC package based on unet.
//
// RPC requests are _not_ concurrent and methods must be explicitly
// registered. However, files may be send as part of the payload.
package urpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// maxFiles determines the maximum file payload.
const maxFiles = 16

// ErrTooManyFiles is returned when too many file descriptors are mapped.
var ErrTooManyFiles = errors.New("too many files")

// ErrUnknownMethod is returned when a method is not known.
var ErrUnknownMethod = errors.New("unknown method")

// errStopped is an internal error indicating the server has been stopped.
var errStopped = errors.New("stopped")

// RemoteError is an error returned by the remote invocation.
//
// This indicates that the RPC transport was correct, but that the called
// function itself returned an error.
type RemoteError struct {
	// Message is the result of calling Error() on the remote error.
	Message string
}

// Error returns the remote error string.
func (r RemoteError) Error() string {
	return r.Message
}

// FilePayload may be _embedded_ in another type in order to send or receive a
// file as a result of an RPC. These are not actually serialized, rather they
// are sent via an accompanying SCM_RIGHTS message (plumbed through the unet
// package).
type FilePayload struct {
	Files []*os.File `json:"-"`
}

// filePayload returns the file. It may be nil.
func (f *FilePayload) filePayload() []*os.File {
	return f.Files
}

// setFilePayload sets the payload.
func (f *FilePayload) setFilePayload(fs []*os.File) {
	f.Files = fs
}

// closeAll closes a slice of files.
func closeAll(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

// filePayloader is implemented only by FilePayload and will be implicitly
// implemented by types that have the FilePayload embedded. Note that there is
// no way to implement these methods other than by embedding FilePayload, due
// to the way unexported method names are mangled.
type filePayloader interface {
	filePayload() []*os.File
	setFilePayload([]*os.File)
}

// clientCall is the client=>server method call on the client side.
type clientCall struct {
	Method string      `json:"method"`
	Arg    interface{} `json:"arg"`
}

// serverCall is the client=>server method call on the server side.
type serverCall struct {
	Method string          `json:"method"`
	Arg    json.RawMessage `json:"arg"`
}

// callResult is the server=>client method call result.
type callResult struct {
	Success bool        `json:"success"`
	Err     string      `json:"err"`
	Result  interface{} `json:"result"`
}

// registeredMethod is method registered with the server.
type registeredMethod struct {
	// fn is the underlying function.
	fn reflect.Value

	// rcvr is the receiver value.
	rcvr reflect.Value

	// argType is a typed argument.
	argType reflect.Type

	// resultType is also a type result.
	resultType reflect.Type
}

// clientState is client metadata.
//
// The following are valid states:
//
// idle - not processing any requests, no close request.
// processing - actively processing, no close request.
// closeRequested - actively processing, pending close.
// closed - client connection has been closed.
//
// The following transitions are possible:
//
// idle -> processing, closed
// processing -> idle, closeRequested
// closeRequested -> closed
//
type clientState int

// See clientState.
const (
	idle clientState = iota
	processing
	closeRequested
	closed
)

// Server is an RPC server.
type Server struct {
	// mu protects all fields, except wg.
	mu sync.Mutex

	// methods is the set of server methods.
	methods map[string]registeredMethod

	// clients is a map of clients.
	clients map[*unet.Socket]clientState

	// wg is a wait group for all outstanding clients.
	wg sync.WaitGroup
}

// NewServer returns a new server.
func NewServer() *Server {
	return &Server{
		methods: make(map[string]registeredMethod),
		clients: make(map[*unet.Socket]clientState),
	}
}

// Register registers the given object as an RPC receiver.
//
// This functions is the same way as the built-in RPC package, but it does not
// tolerate any object with non-conforming methods. Any non-confirming methods
// will lead to an immediate panic, instead of being skipped or an error.
// Panics will also be generated by anonymous objects and duplicate entries.
func (s *Server) Register(obj interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	typ := reflect.TypeOf(obj)

	// If we got a pointer, deref it to the underlying object. We need this to
	// obtain the name of the underlying type.
	typDeref := typ
	if typ.Kind() == reflect.Ptr {
		typDeref = typ.Elem()
	}

	for m := 0; m < typ.NumMethod(); m++ {
		method := typ.Method(m)

		if typDeref.Name() == "" {
			// Can't be anonymous.
			panic("type not named.")
		}

		prettyName := typDeref.Name() + "." + method.Name
		if _, ok := s.methods[prettyName]; ok {
			// Duplicate entry.
			panic(fmt.Sprintf("method %s is duplicated.", prettyName))
		}

		if method.PkgPath != "" {
			// Must be exported.
			panic(fmt.Sprintf("method %s is not exported.", prettyName))
		}
		mtype := method.Type
		if mtype.NumIn() != 3 {
			// Need exactly two arguments (+ receiver).
			panic(fmt.Sprintf("method %s has wrong number of arguments.", prettyName))
		}
		argType := mtype.In(1)
		if argType.Kind() != reflect.Ptr {
			// Need arg pointer.
			panic(fmt.Sprintf("method %s has non-pointer first argument.", prettyName))
		}
		resultType := mtype.In(2)
		if resultType.Kind() != reflect.Ptr {
			// Need result pointer.
			panic(fmt.Sprintf("method %s has non-pointer second argument.", prettyName))
		}
		if mtype.NumOut() != 1 {
			// Need single return.
			panic(fmt.Sprintf("method %s has wrong number of returns.", prettyName))
		}
		if returnType := mtype.Out(0); returnType != reflect.TypeOf((*error)(nil)).Elem() {
			// Need error return.
			panic(fmt.Sprintf("method %s has non-error return value.", prettyName))
		}

		// Register the method.
		s.methods[prettyName] = registeredMethod{
			fn:         method.Func,
			rcvr:       reflect.ValueOf(obj),
			argType:    argType,
			resultType: resultType,
		}
	}
}

// lookup looks up the given method.
func (s *Server) lookup(method string) (registeredMethod, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, ok := s.methods[method]
	return rm, ok
}

// handleOne handles a single call.
func (s *Server) handleOne(client *unet.Socket) error {
	// Unmarshal the call.
	var c serverCall
	newFs, err := unmarshal(client, &c)
	if err != nil {
		// Client is dead.
		return err
	}

	// Start the request.
	if !s.clientBeginRequest(client) {
		// Client is dead; don't process this call.
		return errStopped
	}
	defer s.clientEndRequest(client)

	// Lookup the method.
	rm, ok := s.lookup(c.Method)
	if !ok {
		// Try to serialize the error.
		return marshal(client, &callResult{Err: ErrUnknownMethod.Error()}, nil)
	}

	// Unmarshal the arguments now that we know the type.
	na := reflect.New(rm.argType.Elem())
	if err := json.Unmarshal(c.Arg, na.Interface()); err != nil {
		return marshal(client, &callResult{Err: err.Error()}, nil)
	}

	// Set the file payload as an argument.
	if fp, ok := na.Interface().(filePayloader); ok {
		fp.setFilePayload(newFs)
	}

	// Call the method.
	re := reflect.New(rm.resultType.Elem())
	rValues := rm.fn.Call([]reflect.Value{rm.rcvr, na, re})
	if errVal := rValues[0].Interface(); errVal != nil {
		return marshal(client, &callResult{Err: errVal.(error).Error()}, nil)
	}

	// Set the resulting payload.
	var fs []*os.File
	if fp, ok := re.Interface().(filePayloader); ok {
		fs = fp.filePayload()
		if len(fs) > maxFiles {
			// Ugh. Send an error to the client, despite success.
			return marshal(client, &callResult{Err: ErrTooManyFiles.Error()}, nil)
		}
	}

	// Marshal the result.
	return marshal(client, &callResult{Success: true, Result: re.Interface()}, fs)
}

// clientBeginRequest begins a request.
//
// If true is returned, the request may be processed. If false is returned,
// then the server has been stopped and the request should be skipped.
func (s *Server) clientBeginRequest(client *unet.Socket) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch state := s.clients[client]; state {
	case idle:
		// Mark as processing.
		s.clients[client] = processing
		return true
	case closed:
		// Whoops, how did this happen? Must have closed immediately
		// following the deserialization. Don't let the RPC actually go
		// through, since we won't be able to serialize a proper
		// response.
		return false
	default:
		// Should not happen.
		panic(fmt.Sprintf("expected idle or closed, got %d", state))
	}
}

// clientEndRequest ends a request.
func (s *Server) clientEndRequest(client *unet.Socket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch state := s.clients[client]; state {
	case processing:
		// Return to idle.
		s.clients[client] = idle
	case closeRequested:
		// Close the connection.
		client.Close()
		s.clients[client] = closed
	default:
		// Should not happen.
		panic(fmt.Sprintf("expected processing or requestClose, got %d", state))
	}
}

// clientRegister registers a connection.
//
// See Stop for more context.
func (s *Server) clientRegister(client *unet.Socket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client] = idle
	s.wg.Add(1)
}

// clientUnregister unregisters and closes a connection if necessary.
//
// See Stop for more context.
func (s *Server) clientUnregister(client *unet.Socket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch state := s.clients[client]; state {
	case idle:
		// Close the connection.
		client.Close()
	case closed:
		// Already done.
	default:
		// Should not happen.
		panic(fmt.Sprintf("expected idle or closed, got %d", state))
	}
	delete(s.clients, client)
	s.wg.Done()
}

// handleRegistered handles calls from a registered client.
func (s *Server) handleRegistered(client *unet.Socket) error {
	for {
		// Handle one call.
		if err := s.handleOne(client); err != nil {
			// Client is dead.
			return err
		}
	}
}

// Handle synchronously handles a single client over a connection.
func (s *Server) Handle(client *unet.Socket) error {
	s.clientRegister(client)
	defer s.clientUnregister(client)
	return s.handleRegistered(client)
}

// StartHandling creates a goroutine that handles a single client over a
// connection.
func (s *Server) StartHandling(client *unet.Socket) {
	s.clientRegister(client)
	go func() { // S/R-SAFE: out of scope
		defer s.clientUnregister(client)
		s.handleRegistered(client)
	}()
}

// Stop safely terminates outstanding clients.
//
// No new requests should be initiated after calling Stop. Existing clients
// will be closed after completing any pending RPCs. This method will block
// until all clients have disconnected.
func (s *Server) Stop() {
	// Wait for all outstanding requests.
	defer s.wg.Wait()

	// Close all known clients.
	s.mu.Lock()
	defer s.mu.Unlock()
	for client, state := range s.clients {
		switch state {
		case idle:
			// Close connection now.
			client.Close()
			s.clients[client] = closed
		case processing:
			// Request close when done.
			s.clients[client] = closeRequested
		}
	}
}

// Client is a urpc client.
type Client struct {
	// mu protects all members.
	//
	// It also enforces single-call semantics.
	mu sync.Mutex

	// Socket is the underlying socket for this client.
	//
	// This _must_ be provided and must be closed manually by calling
	// Close.
	Socket *unet.Socket
}

// NewClient returns a new client.
func NewClient(socket *unet.Socket) *Client {
	return &Client{
		Socket: socket,
	}
}

// marshal sends the given FD and json struct.
func marshal(s *unet.Socket, v interface{}, fs []*os.File) error {
	// Marshal to a buffer.
	data, err := json.Marshal(v)
	if err != nil {
		log.Warningf("urpc: error marshalling %s: %s", fmt.Sprintf("%v", v), err.Error())
		return err
	}

	// Write to the socket.
	w := s.Writer(true)
	if fs != nil {
		var fds []int
		for _, f := range fs {
			fds = append(fds, int(f.Fd()))
		}
		w.PackFDs(fds...)
	}

	// Send.
	for n := 0; n < len(data); {
		cur, err := w.WriteVec([][]byte{data[n:]})
		if n == 0 && cur < len(data) {
			// Don't send FDs anymore. This call is only made on
			// the first successful call to WriteVec, assuming cur
			// is not sufficient to fill the entire buffer.
			w.PackFDs()
		}
		n += cur
		if err != nil {
			log.Warningf("urpc: error writing %v: %s", data[n:], err.Error())
			return err
		}
	}

	// We're done sending the fds to the client. Explicitly prevent fs from
	// being GCed until here. Urpc rpcs often unlink the file to send, relying
	// on the kernel to automatically delete it once the last reference is
	// dropped. Until we successfully call sendmsg(2), fs may contain the last
	// references to these files. Without this explicit reference to fs here,
	// the go runtime is free to assume we're done with fs after the fd
	// collection loop above, since it just sees us copying ints.
	runtime.KeepAlive(fs)

	log.Debugf("urpc: successfully marshalled %d bytes.", len(data))
	return nil
}

// unmarhsal receives an FD (optional) and unmarshals the given struct.
func unmarshal(s *unet.Socket, v interface{}) ([]*os.File, error) {
	// Receive a single byte.
	r := s.Reader(true)
	r.EnableFDs(maxFiles)
	firstByte := make([]byte, 1)

	// Extract any FDs that may be there.
	if _, err := r.ReadVec([][]byte{firstByte}); err != nil {
		return nil, err
	}
	fds, err := r.ExtractFDs()
	if err != nil {
		log.Warningf("urpc: error extracting fds: %s", err.Error())
		return nil, err
	}
	var fs []*os.File
	for _, fd := range fds {
		fs = append(fs, os.NewFile(uintptr(fd), "urpc"))
	}

	// Read the rest.
	d := json.NewDecoder(io.MultiReader(bytes.NewBuffer(firstByte), s))
	// urpc internally decodes / re-encodes the data with interface{} as the
	// intermediate type. We have to unmarshal integers to json.Number type
	// instead of the default float type for those intermediate values, such
	// that when they get re-encoded, their values are not printed out in
	// floating-point formats such as 1e9, which could not be decoded to
	// explicitly typed intergers later.
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		log.Warningf("urpc: error decoding: %s", err.Error())
		for _, f := range fs {
			f.Close()
		}
		return nil, err
	}

	// All set.
	log.Debugf("urpc: unmarshal success.")
	return fs, nil
}

// Call calls a function.
func (c *Client) Call(method string, arg interface{}, result interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Are there files to send?
	var fs []*os.File
	if fp, ok := arg.(filePayloader); ok {
		fs = fp.filePayload()
		if len(fs) > maxFiles {
			return ErrTooManyFiles
		}
	}

	// Marshal the data.
	if err := marshal(c.Socket, &clientCall{Method: method, Arg: arg}, fs); err != nil {
		return err
	}

	// Wait for the response.
	callR := callResult{Result: result}
	newFs, err := unmarshal(c.Socket, &callR)
	if err != nil {
		return err
	}

	// Set the file payload.
	if fp, ok := result.(filePayloader); ok {
		fp.setFilePayload(newFs)
	} else {
		closeAll(newFs)
	}

	// Did an error occur?
	if !callR.Success {
		return RemoteError{Message: callR.Err}
	}

	// All set.
	return nil
}

// Close closes the underlying socket.
//
// Further calls to the client may result in undefined behavior.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Socket.Close()
}
