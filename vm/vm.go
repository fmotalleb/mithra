package vm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"iter"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// 1. Core Definitions & Interfaces
// ============================================================================

// Example: port=80 -> map[""]["port"] = "80".
type Properties map[string]map[string]string

const keyValSize = 2

// parseProperties parses raw tokenized args into a hierarchical map.
// Allocations here are fine (Compilation Phase).
func parseProperties(args [][]byte) (Properties, error) {
	p := make(Properties)

	for _, arg := range args {
		// Split key=value
		parts := bytes.SplitN(arg, []byte{'='}, keyValSize)
		if len(parts) != keyValSize {
			return nil, errors.New("invalid syntax: " + string(arg))
		}

		fullKey := string(parts[0])
		val := string(parts[1])

		// Split group.key (e.g., "expect.status" -> group="expect", key="status")
		var group, key string
		if dotIdx := strings.IndexByte(fullKey, '.'); dotIdx != -1 {
			group = fullKey[:dotIdx]
			key = fullKey[dotIdx+1:]
		} else {
			group = "" // Root namespace
			key = fullKey
		}

		if _, exists := p[group]; !exists {
			p[group] = make(map[string]string)
		}
		p[group][key] = val
	}
	return p, nil
}

// Helpers for extracting typed values.
func (p Properties) GetString(group, key string) (string, bool) {
	if g, ok := p[group]; ok {
		if v, ok := g[key]; ok {
			return v, true
		}
	}
	return "", false
}

func (p Properties) GetBool(group, key string) (bool, error) {
	if g, ok := p[group]; ok {
		if v, ok := g[key]; ok {
			return strconv.ParseBool(v)
		}
	}
	return false, nil
}

func (p Properties) GetInt(group, key string) (int, error) {
	str, ok := p.GetString(group, key)
	if !ok {
		return 0, errors.New("missing " + group + "." + key)
	}
	return strconv.Atoi(str)
}

func (p Properties) GetUint16(group, key string) (uint16, error) {
	str, ok := p.GetString(group, key)
	if !ok {
		return 0, errors.New("missing " + group + "." + key)
	}
	v, err := strconv.ParseUint(str, 10, 16)
	return uint16(v), err
}

func (p Properties) GetDuration(group, key string) (time.Duration, error) {
	str, ok := p.GetString(group, key)
	if !ok {
		return 0, errors.New("missing " + group + "." + key)
	}
	return time.ParseDuration(str)
}

// CompileHeaders creates a pre-formatted byte block for all "header.*" keys.
func (p Properties) CompileHeaders(defaultHost string) []byte {
	var b bytes.Buffer

	// Check if user provided header.host
	headers, hasHeaders := p["header"]
	if !hasHeaders {
		headers = make(map[string]string)
	}

	// Handle Host header specially (must be present)
	if _, ok := headers["host"]; !ok {
		headers["host"] = defaultHost
	}

	// Sort keys for deterministic compilation
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		// key: value\r\n
		b.WriteString(k) // Assuming user typed "header.User-Agent" casing correctly
		b.WriteString(": ")
		b.WriteString(headers[k])
		b.WriteString("\r\n")
	}

	return b.Bytes()
}

// Context holds the state for a single IP execution.
// It is designed to be reused or stack-allocated to minimize GC pressure.
type Context struct {
	IP      net.IP
	TCPConn net.Conn
	TLSConn *tls.Conn
	// Fixed-size scratch buffer for IO operations to avoid per-request allocations.
	Buf [4096]byte
}

// Instruction defines the behavior of a single probe step.
type Instruction interface {
	Execute(ctx *Context) error
	String() string
}

// Program is a sequence of compiled instructions.
type Program []Instruction

// IPIterator abstracts the source of IPv4 addresses.
type IPIterator interface {
	Next() (net.IP, bool)
	Seq() iter.Seq[net.IP]
}

// Result captures the outcome of a probe execution.
type Result struct {
	IP       net.IP
	Success  bool
	Duration time.Duration
	Error    error // Contains failure reason and instruction index
}

// ProbeError wraps failures with context.
type ProbeError struct {
	Index  int
	Reason string
}

func (e *ProbeError) Error() string {
	return "instruction " + strconv.Itoa(e.Index) + " failed: " + e.Reason
}

// ============================================================================
// 2. Parser & Compiler (Zero-Allocation Logic)
// ============================================================================

// Compiler transforms raw bytes into a Program.
// It adheres to strict requirements: index-based, no map dispatch, no regex.
type Compiler struct{}

func NewCompiler() *Compiler {
	return &Compiler{}
}

func (c *Compiler) Compile(input []byte) (Program, error) {
	var program Program
	lines := bytes.Split(input, []byte{'\n'}) // Split is allowed only during compilation

	for i, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Tokenize line: command arg1=val1 arg2=val2 ...
		tokens := splitTokens(line)
		if len(tokens) == 0 {
			continue
		}

		cmd := tokens[0]
		args := tokens[1:]
		var instr Instruction
		var err error

		// Direct byte comparison dispatch (No maps)
		switch {
		case bytes.Equal(cmd, []byte("tcp.connect")):
			instr, err = parseTCPConnect(args)
		case bytes.Equal(cmd, []byte("tls.connect")):
			instr, err = parseTLSConnect(args)
		case bytes.Equal(cmd, []byte("http.get")):
			instr, err = parseHTTPGet(args)
		case bytes.Equal(cmd, []byte("tls.http.get")):
			instr, err = parseTLSHTTPGet(args)
		default:
			return nil, &ProbeError{Index: i, Reason: "unknown command: " + string(cmd)}
		}

		if err != nil {
			return nil, &ProbeError{Index: i, Reason: err.Error()}
		}
		program = append(program, instr)
	}

	return program, nil
}

// splitTokens tokenizes by space/tab without allocating new strings (returns slices of original).
func splitTokens(line []byte) [][]byte {
	var tokens [][]byte
	start := -1
	for i, b := range line {
		isSpace := b == ' ' || b == '\t'
		if !isSpace && start == -1 {
			start = i
		} else if isSpace && start != -1 {
			tokens = append(tokens, line[start:i])
			start = -1
		}
	}
	if start != -1 {
		tokens = append(tokens, line[start:])
	}
	return tokens
}

// ============================================================================
// 3. Instruction Set Implementation
// ============================================================================

// --- 1. TCP Connect ---.
type TCPConnect struct {
	Port    uint16
	Timeout time.Duration
}

func parseTCPConnect(args [][]byte) (Instruction, error) {
	p, err := parseProperties(args)
	if err != nil {
		return nil, err
	}

	t := &TCPConnect{}
	if t.Port, err = p.GetUint16("", "port"); err != nil {
		return nil, err
	}
	if t.Timeout, err = p.GetDuration("", "timeout"); err != nil {
		t.Timeout = time.Second
		// return nil, err
	}

	return t, nil
}

func (t *TCPConnect) Execute(ctx *Context) error {
	addr := net.JoinHostPort(ctx.IP.String(), strconv.Itoa(int(t.Port)))
	conn, err := net.DialTimeout("tcp", addr, t.Timeout)
	if err != nil {
		return err
	}
	// Spec: "Optional open TCP connection". We store it.
	// Spec for TCP connect does not explicitly say "store", but Context does.
	// We close previous if exists to be safe, though spec implies sequential usage.
	if ctx.TCPConn != nil {
		ctx.TCPConn.Close()
	}
	ctx.TCPConn = conn
	return nil
}

func (t *TCPConnect) String() string { return "tcp.connect" }

// --- 2. TLS Connect ---.
type TLSConnect struct {
	Port    uint16
	SNI     string
	Verify  bool
	Timeout time.Duration
}

func parseTLSConnect(args [][]byte) (Instruction, error) {
	p, err := parseProperties(args)
	if err != nil {
		return nil, err
	}

	t := &TLSConnect{}
	if t.Port, err = p.GetUint16("", "port"); err != nil {
		t.Port = 443
		// return nil, err
	}
	if t.Timeout, err = p.GetDuration("", "timeout"); err != nil {
		t.Timeout = time.Second
		// return nil, err
	}

	// Optional params
	if sni, ok := p.GetString("", "sni"); ok {
		t.SNI = sni
	}

	if verify, err := p.GetBool("", "verify"); err == nil {
		t.Verify = verify
	}

	return t, nil
}

func (t *TLSConnect) Execute(ctx *Context) error {
	dialer := &net.Dialer{Timeout: t.Timeout}
	addr := net.JoinHostPort(ctx.IP.String(), strconv.Itoa(int(t.Port)))

	// Create raw TCP connection first
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		ServerName:         t.SNI,
		InsecureSkipVerify: t.Verify,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Set deadline for handshake
	if err := tlsConn.SetDeadline(time.Now().Add(t.Timeout)); err != nil {
		conn.Close()
		return err
	}

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return err
	}

	// Store in context
	ctx.TCPConn = conn // Underlying
	ctx.TLSConn = tlsConn
	return nil
}

func (t *TLSConnect) String() string { return "tls.connect" }

// --- 3. HTTP GET (Plain) ---.
type HTTPGet struct {
	Port        uint16
	Path        string
	Expect      int
	Timeout     time.Duration
	HeaderBytes []byte // Pre-formatted "Key: Value\r\n..."
}

func parseHTTPGet(args [][]byte) (Instruction, error) {
	p, err := parseProperties(args)
	if err != nil {
		return nil, err
	}

	h := &HTTPGet{}
	var ok bool
	// Standard fields
	if h.Port, err = p.GetUint16("", "port"); err != nil {
		// return nil, err
		h.Port = 80
	}
	if h.Path, ok = p.GetString("", "path"); !ok {
		h.Path = "/"
	}

	if h.Expect, err = p.GetInt("expect", "status"); err != nil {
		h.Expect = 200
	}

	if h.Timeout, err = p.GetDuration("", "timeout"); err != nil {
		// return nil, err
		h.Timeout = time.Second
	}

	// Flexible Headers: p["header"]["..."]
	// We pre-compile them into bytes to avoid map lookups at runtime.
	h.HeaderBytes = p.CompileHeaders("")

	return h, nil
}

func (h *HTTPGet) Execute(ctx *Context) error {
	addr := net.JoinHostPort(ctx.IP.String(), strconv.Itoa(int(h.Port)))
	conn, err := net.DialTimeout("tcp", addr, h.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	return performHTTPExchange(conn, h.Path, ctx.IP.String(), h.Expect, h.HeaderBytes, h.Timeout, &ctx.Buf)
}

func (h *HTTPGet) String() string { return "http.get" }

// --- 4. HTTP GET over TLS ---.
type TLSHTTPGet struct {
	Path        string
	Expect      int
	Timeout     time.Duration
	HeaderBytes []byte // Pre-formatted "Key: Value\r\n..."
}

func parseTLSHTTPGet(args [][]byte) (Instruction, error) {
	p, err := parseProperties(args)
	if err != nil {
		return nil, err
	}
	t := &TLSHTTPGet{}
	var ok bool
	if t.Path, ok = p.GetString("", "path"); !ok {
		t.Path = "/"
	}

	if t.Expect, err = p.GetInt("expect", "status"); err != nil {
		t.Expect = 200
	}

	if t.Timeout, err = p.GetDuration("", "timeout"); err != nil {
		// return nil, err
		t.Timeout = time.Second
	}
	// Flexible Headers: p["header"]["..."]
	// We pre-compile them into bytes to avoid map lookups at runtime.
	t.HeaderBytes = p.CompileHeaders("")

	return t, nil
}

func (t *TLSHTTPGet) Execute(ctx *Context) error {
	if ctx.TLSConn == nil {
		return errors.New("precondition failed: no active tls connection")
	}
	// Reuse existing TLS connection
	return performHTTPExchange(ctx.TLSConn, t.Path, ctx.IP.String(), t.Expect, t.HeaderBytes, t.Timeout, &ctx.Buf)
}

func (t *TLSHTTPGet) String() string { return "tls.http.get" }

// ============================================================================
// 4. Runtime Helpers (Low-Level HTTP)
// ============================================================================
const statusShiftFactor = 10

// performHTTPExchange executes a raw HTTP/1.0 request to avoid net/http allocations
// and overhead. It uses the Context's buffer.
func performHTTPExchange(conn net.Conn, path, ip string, expect int, extraHeaders []byte, timeout time.Duration, buf *[4096]byte) error {
	// Set deadline for handshake
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return err
	}
	// Construct Request: GET <path> HTTP/1.0\r\n
	b := buf[:0]
	b = append(b, "GET "...)
	b = append(b, path...)
	b = append(b, " HTTP/1.0\r\n"...)

	// Append Custom Headers (if any)
	// Example: extraHeaders contains "User-Agent: bot\r\nHost: example.com\r\n"
	hasCustomHost := bytes.Contains(extraHeaders, []byte("Host:")) || bytes.Contains(extraHeaders, []byte("host:"))

	if len(extraHeaders) > 0 {
		b = append(b, extraHeaders...)
	}

	// Default Host Header if not overridden
	if !hasCustomHost {
		b = append(b, "Host: "...)
		b = append(b, ip...)
		b = append(b, "\r\n"...)
	}

	// End of Headers
	b = append(b, "\r\n"...)

	// Send
	if _, err := conn.Write(b); err != nil {
		return err
	}

	// ... (Reading and parsing response logic remains identical to previous version) ...

	// Read Response
	n, err := conn.Read(buf[:])
	if err != nil && errors.Is(err, io.EOF) {
		return err
	}
	response := buf[:n]

	// Parse Status Code (Simple integer extraction from "HTTP/1.X 200 OK")
	idx1 := bytes.IndexByte(response, ' ')
	if idx1 == -1 {
		return errors.New("malformed http response")
	}
	idx2 := bytes.IndexByte(response[idx1+1:], ' ')
	if idx2 == -1 {
		return errors.New("malformed http response status")
	}

	statusBytes := response[idx1+1 : idx1+1+idx2]
	statusCode := 0
	for _, c := range statusBytes {
		if c < '0' || c > '9' {
			return errors.New("invalid status code bytes")
		}
		statusCode = statusCode*statusShiftFactor + int(c-'0')
	}

	if statusCode != expect {
		return errors.New("status mismatch: expected " + strconv.Itoa(expect) + " got " + strconv.Itoa(statusCode))
	}

	return nil
}

// ============================================================================
// 5. Virtual Machine Logic
// ============================================================================

// VM executes the program.
type VM struct {
	program Program
}

func New(src []byte) (*VM, error) {
	compiler := NewCompiler()
	prog, err := compiler.Compile(src)
	if err != nil {
		return nil, err
	}
	return &VM{program: prog}, nil
}

func (vm *VM) Run(ctx context.Context, ipSeq iter.Seq[net.IP], callback func(Result)) {
	for ip := range ipSeq {
		if ctx.Err() != nil {
			break
		}
		res := vm.executeIP(ip)
		callback(res)
	}
}

func (vm *VM) executeIP(ip net.IP) Result {
	ctx := Context{IP: ip}
	defer func() {
		if ctx.TLSConn != nil {
			ctx.TLSConn.Close()
		} else if ctx.TCPConn != nil {
			ctx.TCPConn.Close()
		}
	}()
	var start time.Time
	for i, instr := range vm.program {
		start = time.Now()
		if err := instr.Execute(&ctx); err != nil {
			return Result{
				IP:       ip,
				Success:  false,
				Duration: time.Since(start),
				Error:    &ProbeError{Index: i, Reason: err.Error()},
			}
		}
	}

	return Result{IP: ip, Success: true}
}
