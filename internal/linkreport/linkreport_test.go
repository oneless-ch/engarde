package linkreport

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Report{Name: "5G", Sent: 1 << 40, Received: 12345, Dropped: 7}
	out, err := Decode(Encode(in))
	if err != nil || out != in {
		t.Fatalf("round trip: got %+v, %v; want %+v", out, err, in)
	}
}

func TestNeverLooksLikeWireGuard(t *testing.T) {
	// WireGuard message types are 1..4 in the first byte.
	b := Encode(Report{Name: "wifi"})
	if b[0] >= 1 && b[0] <= 4 {
		t.Fatalf("first byte %d collides with a WireGuard message type", b[0])
	}
	for typ := byte(1); typ <= 4; typ++ {
		if IsReport([]byte{typ, 0, 0, 0}) {
			t.Fatalf("WireGuard type %d taken for a report", typ)
		}
	}
}

func TestLongNamesAreTruncated(t *testing.T) {
	out, err := Decode(Encode(Report{Name: strings.Repeat("x", 100)}))
	if err != nil || len(out.Name) != MaxName {
		t.Fatalf("got %q, %v", out.Name, err)
	}
}

func TestMalformedIsRefused(t *testing.T) {
	good := Encode(Report{Name: "lte", Sent: 1})
	cases := map[string][]byte{
		"empty":         {},
		"magic only":    {Magic},
		"other version": append([]byte{Magic, Version + 1}, good[2:]...),
		"short":         good[:len(good)-1],
		"long":          append(append([]byte{}, good...), 0),
		"name overrun":  {Magic, Version, MaxName + 1},
	}
	for name, b := range cases {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
