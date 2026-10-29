// modify from https://github.com/XTLS/REALITY/blob/83f6217/record_detect.go

package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// realityPostHandshakeRecordsLens maps "dest sni alpn" to the lengths of the
// encrypted records the target sends after the handshake (e.g. NewSessionTicket),
// or to false while the detection is still running.
var realityPostHandshakeRecordsLens sync.Map

// realityMaxCCSMsgCount maps "dest sni alpn" to the number of consecutive
// ChangeCipherSpec records the target tolerates.
var realityMaxCCSMsgCount sync.Map

const realityDetectTimeout = 15 * time.Second

func realityDetectKey(dest, serverName string, alpnProtocols []string) string {
	key := dest + " " + serverName
	if len(alpnProtocols) == 0 {
		return key + " 0"
	} else if alpnProtocols[0] == "h2" {
		return key + " 2"
	}
	return key + " 1"
}

// DetectPostHandshakeRecordsLens probes the REALITY target once per server name
// and ALPN class, so the server can mimic the target's post-handshake records
// and its tolerance for useless records. It returns immediately; repeated calls
// for the same target are ignored.
func DetectPostHandshakeRecordsLens(config *RealityConfig) {
	for serverName := range config.ServerNames {
		for alpn := 0; alpn < 3; alpn++ {
			var nextProtos []string
			switch alpn {
			case 1:
				nextProtos = []string{"http/1.1"}
			case 2:
				nextProtos = []string{"h2", "http/1.1"}
			}
			key := realityDetectKey(config.Dest, serverName, nextProtos)
			if _, loaded := realityPostHandshakeRecordsLens.LoadOrStore(key, false); loaded {
				continue
			}
			fingerprint := HelloGolang
			if alpn == 2 {
				fingerprint = HelloChrome_Auto
			}
			go realityDetectPostHandshakeRecords(config, key, serverName, nextProtos, fingerprint)
			go realityDetectCCSTolerance(config, key, serverName, nextProtos, fingerprint)
		}
	}
}

func realityDialTarget(config *RealityConfig) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), realityDetectTimeout)
	defer cancel()
	if config.DialContext != nil {
		return config.DialContext(ctx, config.Type, config.Dest)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, config.Type, config.Dest)
}

func realityDetectPostHandshakeRecords(config *RealityConfig, key string, serverName string, nextProtos []string, fingerprint ClientHelloID) {
	defer func() {
		recover()
		if value, _ := realityPostHandshakeRecordsLens.Load(key); value == false {
			realityPostHandshakeRecordsLens.Store(key, []int{})
		}
	}()
	target, err := realityDialTarget(config)
	if err != nil {
		return
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(realityDetectTimeout))
	detectConn := &realityPostHandshakeRecordDetectConn{Conn: target, key: key}
	uConn := UClient(detectConn, &Config{
		ServerName: serverName,
		NextProtos: nextProtos,
	}, fingerprint)
	if err = uConn.Handshake(); err != nil {
		return
	}
	io.Copy(io.Discard, uConn)
}

func realityDetectCCSTolerance(config *RealityConfig, key string, serverName string, nextProtos []string, fingerprint ClientHelloID) {
	defer func() {
		recover()
	}()
	target, err := realityDialTarget(config)
	if err != nil {
		return
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(2 * realityDetectTimeout))
	uConn := UClient(&realityCCSDetectConn{Conn: target, key: key}, &Config{
		ServerName: serverName,
		NextProtos: nextProtos,
	}, fingerprint)
	uConn.Handshake()
}

type realityPostHandshakeRecordDetectConn struct {
	net.Conn
	key     string
	ccsSent bool
}

func (c *realityPostHandshakeRecordDetectConn) Write(b []byte) (int, error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.ccsSent = true
	}
	return c.Conn.Write(b)
}

func (c *realityPostHandshakeRecordDetectConn) Read(b []byte) (int, error) {
	if !c.ccsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	var postHandshakeRecordsLens []int
	for len(data) >= recordHeaderLen && bytes.Equal(data[:3], []byte{23, 3, 3}) {
		length := int(binary.BigEndian.Uint16(data[3:5])) + recordHeaderLen
		if length > len(data) {
			break
		}
		postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
		data = data[length:]
	}
	realityPostHandshakeRecordsLens.Store(c.key, postHandshakeRecordsLens)
	return 0, io.EOF
}

var realityCCSMsg = []byte{0x14, 0x3, 0x3, 0x0, 0x1, 0x1}

type realityCCSDetectConn struct {
	net.Conn
	key string
}

func (c *realityCCSDetectConn) Write(b []byte) (int, error) {
	if len(b) < 3 || !bytes.Equal(b[:3], []byte{20, 3, 3}) {
		return c.Conn.Write(b)
	}
	var hasAlert atomic.Bool
	go func() {
		defer hasAlert.Store(true)
		buf := make([]byte, 512)
		for {
			_, err := c.Conn.Read(buf)
			if err != nil || buf[0] == byte(recordTypeAlert) {
				return
			}
		}
	}()
	sendProbePayload := func(count int) bool {
		c.Conn.Write(bytes.Repeat(realityCCSMsg, count))
		time.Sleep(time.Second)
		return hasAlert.Load()
	}
	switch {
	case sendProbePayload(2):
		realityMaxCCSMsgCount.Store(c.key, 1)
	case sendProbePayload(15):
		realityMaxCCSMsgCount.Store(c.key, 16)
	case sendProbePayload(16):
		realityMaxCCSMsgCount.Store(c.key, 32)
	default:
		realityMaxCCSMsgCount.Store(c.key, math.MaxInt)
	}
	return c.Conn.Write(b)
}

// realityWritePostHandshakeRecords waits for the detection of the target to
// finish, then mimics its post-handshake records and useless record tolerance.
func (c *Conn) realityWritePostHandshakeRecords(key string) error {
	deadline := time.Now().Add(realityDetectTimeout + 5*time.Second)
	for {
		value, loaded := realityPostHandshakeRecordsLens.Load(key)
		if !loaded {
			return nil
		}
		postHandshakeRecordsLens, done := value.([]int)
		if !done {
			if time.Now().After(deadline) {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if maxUseless, ok := realityMaxCCSMsgCount.Load(key); ok {
			c.realityMaxUselessRecords = maxUseless.(int)
		}
		if len(postHandshakeRecordsLens) == 0 {
			return nil
		}
		c.out.Lock()
		defer c.out.Unlock()
		recordAEAD, ok := c.out.cipher.(aead)
		if !ok {
			return nil
		}
		for _, length := range postHandshakeRecordsLens {
			if length < recordHeaderLen+recordAEAD.Overhead()+1 {
				continue
			}
			plainText := make([]byte, length-recordAEAD.Overhead())
			plainText[0] = byte(recordTypeApplicationData)
			plainText[1] = 3
			plainText[2] = 3
			plainText[3] = byte((length - recordHeaderLen) >> 8)
			plainText[4] = byte(length - recordHeaderLen)
			plainText[5] = byte(recordTypeApplicationData)
			record := recordAEAD.Seal(plainText[:recordHeaderLen], c.out.seq[:], plainText[recordHeaderLen:], plainText[:recordHeaderLen])
			c.out.incSeq()
			if _, err := c.write(record); err != nil {
				return err
			}
		}
		_, err := c.flush()
		return err
	}
}
