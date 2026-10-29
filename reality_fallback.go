package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/utls/internal/mlkem"
	"github.com/metacubex/utls/internal/ratelimit"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ErrFallbackHandled is returned by RealityServer when the connection failed
// REALITY authentication and was relayed to the fallback target.
var ErrFallbackHandled = errors.New("REALITY: connection handled by fallback")

// RealityFallbackOptions relays connections that fail REALITY authentication to
// a fallback target, replaying the bytes already received, instead of mirroring
// them to Dest within the handshake.
type RealityFallbackOptions struct {
	// Server is an IP, a domain or a unix socket path ("/path" or "unix:/path").
	// When empty, Dest is used.
	Server     string
	ServerPort uint16
	// IdleTimeout closes the relay after no data flows in either direction.
	IdleTimeout time.Duration
	// BytesPerSec limits each direction of a relayed connection; 0 means unlimited.
	BytesPerSec uint64
	// ConnectionsPerSec limits how many connections may fall back per second;
	// excess connections are closed. 0 means unlimited.
	ConnectionsPerSec float64

	limiterOnce sync.Once
	limiter     *ratelimit.Bucket
}

const realityMaxClientHelloSize = 64 * 1024

func (o *RealityFallbackOptions) allow() bool {
	if o.ConnectionsPerSec <= 0 {
		return true
	}
	o.limiterOnce.Do(func() {
		capacity := int64(math.Ceil(o.ConnectionsPerSec))
		if capacity < 1 {
			capacity = 1
		}
		o.limiter = ratelimit.NewBucketWithRate(o.ConnectionsPerSec, capacity)
	})
	return o.limiter.TakeAvailable(1) == 1
}

// realityReadClientHello reads TLS handshake records until a complete handshake
// message is available. raw holds every byte read, so it can be replayed.
func realityReadClientHello(conn net.Conn) (raw []byte, message []byte, err error) {
	var header [recordHeaderLen]byte
	for len(raw) < realityMaxClientHelloSize {
		_, err = io.ReadFull(conn, header[:])
		raw = append(raw, header[:]...)
		if err != nil {
			return raw, nil, err
		}
		if recordType(header[0]) != recordTypeHandshake {
			return raw, nil, errors.New("REALITY: not a handshake record")
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if length == 0 || length > maxPlaintext {
			return raw, nil, errors.New("REALITY: invalid record length")
		}
		start := len(raw)
		raw = append(raw, make([]byte, length)...)
		n, err := io.ReadFull(conn, raw[start:])
		raw = raw[:start+n]
		if err != nil {
			return raw, nil, err
		}
		message = append(message, raw[start:]...)
		if len(message) >= 4 {
			if message[0] != typeClientHello {
				return raw, nil, errors.New("REALITY: not a client hello")
			}
			messageLength := 4 + (int(message[1])<<16 | int(message[2])<<8 | int(message[3]))
			if messageLength > realityMaxClientHelloSize {
				return raw, nil, errors.New("REALITY: client hello too large")
			}
			if len(message) >= messageLength {
				return raw, message[:messageLength], nil
			}
		}
	}
	return raw, nil, errors.New("REALITY: client hello too large")
}

// realityAuthenticate repeats the REALITY client authentication on a parsed
// Client Hello without touching the connection.
func realityAuthenticate(config *RealityConfig, hello *clientHelloMsg) bool {
	if !config.ServerNames[hello.serverName] || len(hello.sessionId) != 32 || len(hello.original) < 39+32 || len(hello.random) != 32 {
		return false
	}
	var supportsTLS13 bool
	for _, version := range hello.supportedVersions {
		if version == VersionTLS13 {
			supportsTLS13 = true
			break
		}
	}
	if !supportsTLS13 {
		return false
	}
	var peerPub []byte
	for _, keyShare := range hello.keyShares {
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			peerPub = keyShare.data
			break
		}
	}
	if peerPub == nil {
		for _, keyShare := range hello.keyShares {
			if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
				peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]
				break
			}
		}
	}
	if peerPub == nil {
		return false
	}
	authKey, err := curve25519.X25519(config.PrivateKey, peerPub)
	if err != nil {
		return false
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return false
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	additionalData := append([]byte{}, hello.original...)
	copy(additionalData[39:39+32], make([]byte, 32))
	plainText, err := aead.Open(nil, hello.random[20:], hello.sessionId, additionalData)
	if err != nil || len(plainText) < 16 {
		return false
	}
	clientVer := plainText[:3]
	clientTime := time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
	var clientShortId [8]byte
	copy(clientShortId[:], plainText[8:])
	return (config.MinClientVer == nil || realityValue(clientVer...) >= realityValue(config.MinClientVer...)) &&
		(config.MaxClientVer == nil || realityValue(clientVer...) <= realityValue(config.MaxClientVer...)) &&
		(config.MaxTimeDiff == 0 || config.time().Sub(clientTime).Abs() <= config.MaxTimeDiff) &&
		config.ShortIds[clientShortId]
}

type realityPrefixConn struct {
	net.Conn
	prefix []byte
}

func (c *realityPrefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *realityPrefixConn) CloseWrite() error {
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *realityPrefixConn) NetConn() net.Conn {
	return c.Conn
}

// realityFallbackPrecheck authenticates the Client Hello first when a fallback is
// configured. Valid clients continue with the returned connection, which replays
// the bytes already read; others are relayed to the fallback target.
func realityFallbackPrecheck(ctx context.Context, conn net.Conn, config *RealityConfig) (net.Conn, error) {
	raw, message, err := realityReadClientHello(conn)
	if err == nil {
		hello := new(clientHelloMsg)
		if hello.unmarshal(message) && realityAuthenticate(config, hello) {
			return &realityPrefixConn{Conn: conn, prefix: raw}, nil
		}
	}
	if len(raw) == 0 && err != nil {
		conn.Close()
		return nil, err
	}
	return nil, realityRelayFallback(ctx, conn, config, raw)
}

func realityFallbackDestination(config *RealityConfig) (network string, address string) {
	fallback := config.Fallback
	server := fallback.Server
	switch {
	case server == "":
		return config.Type, config.Dest
	case strings.HasPrefix(server, "unix:"):
		return "unix", strings.TrimPrefix(server, "unix:")
	case strings.HasPrefix(server, "/"):
		return "unix", server
	}
	port := fallback.ServerPort
	if port == 0 {
		if _, destPort, err := net.SplitHostPort(config.Dest); err == nil {
			return "tcp", net.JoinHostPort(server, destPort)
		}
		port = 443
	}
	return "tcp", net.JoinHostPort(server, strconv.Itoa(int(port)))
}

func realityRelayFallback(ctx context.Context, conn net.Conn, config *RealityConfig, clientData []byte) error {
	defer conn.Close()
	fallback := config.Fallback
	if !fallback.allow() {
		if config.Log != nil {
			config.Log("REALITY remoteAddr: %v fallback rate limited", conn.RemoteAddr())
		}
		return ErrFallbackHandled
	}
	conn.SetDeadline(time.Time{})
	idleTimeout := fallback.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	network, address := realityFallbackDestination(config)
	dialCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), idleTimeout)
	var (
		target net.Conn
		err    error
	)
	if network == "unix" || config.DialContext == nil {
		var dialer net.Dialer
		target, err = dialer.DialContext(dialCtx, network, address)
	} else {
		target, err = config.DialContext(dialCtx, network, address)
	}
	cancel()
	if err != nil {
		return errors.New("REALITY: dial fallback " + address + ": " + err.Error())
	}
	defer target.Close()
	if config.Log != nil {
		config.Log("REALITY remoteAddr: %v relayed to fallback %v", conn.RemoteAddr(), address)
	}
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	if len(clientData) > 0 {
		if _, err = target.Write(clientData); err != nil {
			return ErrFallbackHandled
		}
	}
	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			close(done)
			conn.Close()
			target.Close()
		})
	}
	copyDirection := func(destination net.Conn, source net.Conn) {
		defer closeAll()
		var bucket *ratelimit.Bucket
		if fallback.BytesPerSec > 0 {
			bucket = ratelimit.NewBucketWithRate(float64(fallback.BytesPerSec), int64(fallback.BytesPerSec))
		}
		buffer := make([]byte, 16*1024)
		for {
			n, err := source.Read(buffer)
			if n > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if bucket != nil {
					bucket.Wait(int64(n))
				}
				if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
					return
				}
				lastActivity.Store(time.Now().UnixNano())
			}
			if err != nil {
				return
			}
		}
	}
	go copyDirection(target, conn)
	go copyDirection(conn, target)
	ticker := time.NewTicker(idleTimeout / 4)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return ErrFallbackHandled
		case now := <-ticker.C:
			if now.Sub(time.Unix(0, lastActivity.Load())) > idleTimeout {
				closeAll()
				return ErrFallbackHandled
			}
		}
	}
}
