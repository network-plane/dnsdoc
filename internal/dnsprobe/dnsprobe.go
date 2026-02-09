package dnsprobe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Answer struct {
	Value string
	TTL   uint32
}

type Flags struct {
	QR bool
	AA bool
	TC bool
	RD bool
	RA bool
	AD bool
	CD bool
}

type Timings struct {
	Total     time.Duration
	Dial      time.Duration
	Pack      time.Duration
	Write     time.Duration
	Read      time.Duration
	Unpack    time.Duration
	RTTApprox time.Duration
}

type Result struct {
	Server            string
	Network           string
	LocalAddr         string
	RemoteAddr        string
	Timeout           time.Duration
	QName             string
	RCode             string
	MsgID             uint16
	Flags             Flags
	AnswerCount       int
	NSCount           int
	ExtraCount        int
	QuerySizeBytes    int
	ResponseSizeBytes int
	Answers           []Answer
	Timings           Timings
}

type Benchmark struct {
	Attempts int
	Success  int
	Fail     int
	Avg      Timings
}

func SystemDefaultDNSServer() (string, error) {
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return "", err
		}
		if len(cfg.Servers) == 0 {
			return "", errors.New("no nameserver entries in /etc/resolv.conf")
		}
		return net.JoinHostPort(cfg.Servers[0], cfg.Port), nil
	}
	return "", fmt.Errorf("unsupported auto-detection on %s; pass dns-server explicitly (e.g. 1.1.1.1 or 1.1.1.1:53)", runtime.GOOS)
}

func ProbeA(ctx context.Context, server string, qname string, timeout time.Duration) (Result, error) {
	server = normalizeServer(server)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	msg.RecursionDesired = true
	msg.CheckingDisabled = false

	startTotal := time.Now()

	startPack := time.Now()
	wire, err := msg.Pack()
	packDur := time.Since(startPack)
	if err != nil {
		return Result{}, err
	}

	network := "udp"
	d := net.Dialer{Timeout: timeout}
	startDial := time.Now()
	conn, err := d.DialContext(ctx, network, server)
	dialDur := time.Since(startDial)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	local := conn.LocalAddr().String()
	remote := conn.RemoteAddr().String()

	startWrite := time.Now()
	nw, err := conn.Write(wire)
	writeDur := time.Since(startWrite)
	if err != nil {
		return Result{}, err
	}

	buf := make([]byte, 65535)
	startRead := time.Now()
	nr, err := conn.Read(buf)
	readDur := time.Since(startRead)
	if err != nil {
		return Result{}, err
	}

	var resp dns.Msg
	startUnpack := time.Now()
	if err := resp.Unpack(buf[:nr]); err != nil {
		return Result{}, err
	}
	unpackDur := time.Since(startUnpack)

	totalDur := time.Since(startTotal)

	r := Result{
		Server:            server,
		Network:           network,
		LocalAddr:         local,
		RemoteAddr:        remote,
		Timeout:           timeout,
		QName:             qname,
		RCode:             dns.RcodeToString[resp.Rcode],
		MsgID:             resp.Id,
		Flags: Flags{
			QR: resp.Response,
			AA: resp.Authoritative,
			TC: resp.Truncated,
			RD: resp.RecursionDesired,
			RA: resp.RecursionAvailable,
			AD: resp.AuthenticatedData,
			CD: resp.CheckingDisabled,
		},
		AnswerCount:       len(resp.Answer),
		NSCount:           len(resp.Ns),
		ExtraCount:        len(resp.Extra),
		QuerySizeBytes:    nw,
		ResponseSizeBytes: nr,
		Timings: Timings{
			Total:     totalDur,
			Dial:      dialDur,
			Pack:      packDur,
			Write:     writeDur,
			Read:      readDur,
			Unpack:    unpackDur,
			RTTApprox: writeDur + readDur,
		},
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			r.Answers = append(r.Answers, Answer{Value: a.A.String(), TTL: a.Hdr.Ttl})
		}
	}

	return r, nil
}

func BenchmarkSerial(ctx context.Context, server, qname string, timeout time.Duration, n int) Benchmark {
	var sum Timings
	var ok, fail int

	for i := 0; i < n; i++ {
		r, err := ProbeA(ctx, server, qname, timeout)
		if err != nil {
			fail++
			continue
		}
		ok++
		sum = add(sum, r.Timings)
	}

	return Benchmark{
		Attempts: n,
		Success:  ok,
		Fail:     fail,
		Avg:      avg(sum, ok),
	}
}

func BenchmarkConcurrent(ctx context.Context, server, qname string, timeout time.Duration, n int) Benchmark {
	type one struct {
		t   Timings
		err error
	}

	ch := make(chan one, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			r, err := ProbeA(ctx, server, qname, timeout)
			if err != nil {
				ch <- one{err: err}
				return
			}
			ch <- one{t: r.Timings}
		}()
	}

	wg.Wait()
	close(ch)

	var sum Timings
	var ok, fail int
	for v := range ch {
		if v.err != nil {
			fail++
			continue
		}
		ok++
		sum = add(sum, v.t)
	}

	return Benchmark{
		Attempts: n,
		Success:  ok,
		Fail:     fail,
		Avg:      avg(sum, ok),
	}
}

func normalizeServer(s string) string {
	if strings.Contains(s, ":") {
		if _, _, err := net.SplitHostPort(s); err == nil {
			return s
		}
	}
	return net.JoinHostPort(s, "53")
}

func add(a, b Timings) Timings {
	return Timings{
		Total:     a.Total + b.Total,
		Dial:      a.Dial + b.Dial,
		Pack:      a.Pack + b.Pack,
		Write:     a.Write + b.Write,
		Read:      a.Read + b.Read,
		Unpack:    a.Unpack + b.Unpack,
		RTTApprox: a.RTTApprox + b.RTTApprox,
	}
}

func avg(s Timings, n int) Timings {
	if n <= 0 {
		return Timings{}
	}
	den := time.Duration(n)
	return Timings{
		Total:     s.Total / den,
		Dial:      s.Dial / den,
		Pack:      s.Pack / den,
		Write:     s.Write / den,
		Read:      s.Read / den,
		Unpack:    s.Unpack / den,
		RTTApprox: s.RTTApprox / den,
	}
}

func RandomDomain128WithCOM() (string, error) {
	l1, err := randomLabel(60)
	if err != nil {
		return "", err
	}
	l2, err := randomLabel(63)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s.com", l1, l2), nil
}

func randomLabel(n int) (string, error) {
	if n < 1 || n > 63 {
		return "", fmt.Errorf("label length must be 1..63, got %d", n)
	}
	const mid = "abcdefghijklmnopqrstuvwxyz0123456789-"
	const edge = "abcdefghijklmnopqrstuvwxyz0123456789"

	out := make([]byte, n)

	if err := fillFromCharset(out[:1], edge); err != nil {
		return "", err
	}
	if n > 2 {
		if err := fillFromCharset(out[1:n-1], mid); err != nil {
			return "", err
		}
	}
	if n > 1 {
		if err := fillFromCharset(out[n-1:], edge); err != nil {
			return "", err
		}
	}
	return string(out), nil
}

func fillFromCharset(dst []byte, charset string) error {
	if len(dst) == 0 {
		return nil
	}
	b := make([]byte, len(dst))
	if _, err := rand.Read(b); err != nil {
		return err
	}
	for i := range dst {
		dst[i] = charset[int(b[i])%len(charset)]
	}
	return nil
}
func LooksLikeServer(s string) bool {
	// Accept ip[:port], host[:port]
	if strings.Contains(s, ":") {
		if _, _, err := net.SplitHostPort(s); err == nil {
			return true
		}
	}
	// Heuristic: if it parses as IP or has no dots beyond TLD length, assume server
	if net.ParseIP(s) != nil {
		return true
	}
	// If it contains a port-like suffix
	if h, p, err := net.SplitHostPort(s + ":53"); err == nil && h != "" && p != "" {
		return true
	}
	return false
}
