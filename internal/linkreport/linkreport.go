// Package linkreport is the one control datagram engarde's two ends exchange
// besides WireGuard's own traffic: a client link telling the server which
// link it is and what it has counted.
//
// The server only ever sees addresses, and addresses change (CGNAT rebinding,
// a modem getting a new IP). Every ~5 s each client link sends a report on its
// own socket; the server learns address → link name from it, and pairs the
// client's counters with its own for that address at the moment the report
// arrives, so delivery each way can be computed without clock alignment.
//
// Wire format (big endian):
//
//	0xEE  version(1)  nameLen(u8)  name[nameLen]  sent(u64)  received(u64)  dropped(u64)
//
// 0xEE is never the first byte of a WireGuard message (types 1–4, followed by
// three zero bytes), so an old server that forwards a report to WireGuard has
// it dropped there silently, and an old client simply sends none.
package linkreport

import (
	"encoding/binary"
	"errors"
)

// Magic is the first byte of every report.
const Magic = 0xEE

// Version is the report layout this build writes and reads.
const Version = 1

// MaxName bounds the link name; a longer one is truncated on encode.
const MaxName = 32

// Report is one link's self-description.
type Report struct {
	Name     string
	Sent     uint64 // data datagrams this link wrote (reports excluded)
	Received uint64 // data datagrams this link read (reports excluded)
	Dropped  uint64 // copies this link dropped (queue full or write deadline)
}

// ErrNotReport means the datagram is not a report of a version this build reads.
var ErrNotReport = errors.New("not a link report")

// IsReport tells a report from WireGuard traffic by its first byte alone.
func IsReport(b []byte) bool {
	return len(b) > 0 && b[0] == Magic
}

// Encode renders r as one datagram.
func Encode(r Report) []byte {
	name := r.Name
	if len(name) > MaxName {
		name = name[:MaxName]
	}
	b := make([]byte, 3+len(name)+24)
	b[0], b[1], b[2] = Magic, Version, byte(len(name))
	copy(b[3:], name)
	p := b[3+len(name):]
	// PutUint64, not AppendUint64: go.mod still says go 1.16.
	binary.BigEndian.PutUint64(p[0:8], r.Sent)
	binary.BigEndian.PutUint64(p[8:16], r.Received)
	binary.BigEndian.PutUint64(p[16:24], r.Dropped)
	return b
}

// Decode parses a datagram that IsReport accepted.
func Decode(b []byte) (Report, error) {
	if len(b) < 3 || b[0] != Magic || b[1] != Version {
		return Report{}, ErrNotReport
	}
	n := int(b[2])
	if n > MaxName || len(b) != 3+n+24 {
		return Report{}, ErrNotReport
	}
	p := b[3+n:]
	return Report{
		Name:     string(b[3 : 3+n]),
		Sent:     binary.BigEndian.Uint64(p[0:8]),
		Received: binary.BigEndian.Uint64(p[8:16]),
		Dropped:  binary.BigEndian.Uint64(p[16:24]),
	}, nil
}
