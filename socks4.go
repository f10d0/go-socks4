// Package socks4 implements socks4 and socks4a support for net/proxy
// Just import `_ "github.com/bdandy/go-socks4"` to add `socks4` support
package socks4 // import _ "github.com/bdandy/go-socks4"

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	errors "github.com/bdandy/go-errors"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/proxy"
)

const (
	socksVersion = 0x04
	socksConnect = 0x01
	// nolint
	socksBind = 0x02

	accessGranted       = 0x5a
	accessRejected      = 0x5b
	accessIdentRequired = 0x5c
	accessIdentFailed   = 0x5d

	minRequestLen = 8
)

const (
	ErrWrongNetwork    = errors.String("network should be tcp or tcp4")          // socks4 protocol supports only tcp/ip v4 connections
	ErrDialFailed      = errors.String("socks4 dial")                            // connection to socks4 server failed
	ErrWrongAddr       = errors.String("wrong addr: %s")                         // provided addr should be in format host:port
	ErrConnRejected    = errors.String("connection to remote host was rejected") // connection was rejected by proxy
	ErrIdentRequired   = errors.String("valid ident required")                   // proxy requires valid ident. Check Ident variable
	ErrIO              = errors.String("i\\o error")                             // some i\o error happened
	ErrHostUnknown     = errors.String("unable to find IP address of host %s")   // host dns resolving failed
	ErrInvalidResponse = errors.String("unknown socks4 server response %v")      // proxy reply contains invalid data
	ErrBuffer          = errors.String("unable write into buffer")
)

var Ident = "nobody@0.0.0.0"

func init() {
	register := func(scheme string) {
		proxy.RegisterDialerType(scheme, func(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
			return newSocks4(u, d), nil
		})
	}
	register("socks4")
	register("socks4a")
}

type Error = errors.Error

type socks4 struct {
	url    *url.URL
	dialer proxy.Dialer
}

var dnsSharedCache = cache.New(cache.NoExpiration, 10*time.Minute)
var dnsClient = &dns.Client{Timeout: 4 * time.Second}

func newSocks4(u *url.URL, d proxy.Dialer) *socks4 {
	return &socks4{
		url:    u,
		dialer: d,
	}
}

// Dial implements proxy.Dialer interface
func (s socks4) Dial(network, addr string) (c net.Conn, err error) {
	if network != "tcp" && network != "tcp4" {
		return nil, ErrWrongNetwork
	}

	c, err = s.dialer.Dial(network, s.url.Host)
	if err != nil {
		return nil, ErrDialFailed.New().Wrap(err)
	}
	// close connection later if we got an error
	defer func() {
		if err != nil && c != nil {
			_ = c.Close()
		}
	}()

	host, port, err := s.parseAddr(addr)
	if err != nil {
		return nil, ErrWrongAddr.New(addr).Wrap(err)
	}

	var ip net.IP
	if !s.isSocks4a() {
		if ip = net.ParseIP(host); ip == nil {
			if ip, err = s.lookupAddr(host); err != nil {
				return nil, ErrHostUnknown.New(host).Wrap(err)
			}
		}
	}

	req, err := request{Host: host, Port: port, IP: ip, Is4a: s.isSocks4a()}.Bytes()
	if err != nil {
		return nil, ErrBuffer.New().Wrap(err)
	}

	var i int
	i, err = c.Write(req)
	if err != nil {
		return c, ErrIO.New().Wrap(err)
	} else if i < minRequestLen {
		return c, ErrIO.New().Wrap(io.ErrShortWrite)
	}

	var resp [8]byte
	i, err = c.Read(resp[:])
	if err != nil && err != io.EOF {
		return c, ErrIO.New().Wrap(err)
	} else if i != 8 {
		return c, ErrIO.New().Wrap(io.ErrUnexpectedEOF)
	}

	switch resp[1] {
	case accessGranted:
		return c, nil
	case accessIdentRequired, accessIdentFailed:
		return c, ErrIdentRequired
	case accessRejected:
		return c, ErrConnRejected
	default:
		return c, ErrInvalidResponse.New(resp[1])
	}
}

func (s socks4) lookupAddr(host string) (net.IP, error) {
	// cache hit
	if v, ok := dnsSharedCache.Get(host); ok {
		return v.(net.IP), nil
	}

	// query manually
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

	// ask system's default resolver
	resp, _, err := dnsClient.Exchange(msg, getSystemDNSServer())
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
	}

	var ip net.IP
	ttl := uint32(0)
	for _, ans := range resp.Answer {
		if aRec, ok := ans.(*dns.A); ok {
			if ip == nil {
				ip = aRec.A.To4()
				ttl = aRec.Hdr.Ttl
			} else if aRec.Hdr.Ttl < ttl {
				ttl = aRec.Hdr.Ttl
			}
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("no A record for %s", host)
	}

	dnsSharedCache.Set(host, ip, time.Duration(ttl)*time.Second)
	return ip, nil
}

func getSystemDNSServer() string {
	cfg, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	if len(cfg.Servers) == 0 { // fallback
		return "8.8.8.8:53"
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port)
}

func (s socks4) isSocks4a() bool {
	return s.url.Scheme == "socks4a"
}

func (s socks4) parseAddr(addr string) (host string, iport int, err error) {
	var port string

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}

	iport, err = strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}

	return
}
