package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/porech/engarde/v2/internal/linkreport"
)

func resetClients() {
	clients = make(map[string]*ConnectedClient)
	clientsMutex = &sync.RWMutex{}
}

var addr = &net.UDPAddr{IP: net.IPv4(178, 197, 1, 2), Port: 40001}

func TestAReportNeverRegistersAnAddress(t *testing.T) {
	resetClients()
	report := linkreport.Encode(linkreport.Report{Name: "5G"})
	if handleClientDatagram(report, addr, time.Now()) {
		t.Fatal("a report was forwarded to WireGuard")
	}
	if len(clients) != 0 {
		t.Fatal("a report from an unknown address created a client entry")
	}
}

func TestDataRegistersAndCountsAndIsForwarded(t *testing.T) {
	resetClients()
	data := []byte{4, 0, 0, 0, 1, 2, 3, 4} // a WireGuard transport message
	if !handleClientDatagram(data, addr, time.Now()) {
		t.Fatal("WireGuard data not forwarded")
	}
	c := clients["178.197.1.2:40001"]
	if c == nil || c.ReceivedFrom != 1 || c.ReceivedFromBytes != uint64(len(data)) {
		t.Fatalf("client after one datagram: %+v", c)
	}
}

func TestAReportIsPairedWithTheServerCountersAtArrival(t *testing.T) {
	resetClients()
	now := time.Unix(1000, 0)
	data := []byte{4, 0, 0, 0}
	for i := 0; i < 3; i++ {
		handleClientDatagram(data, addr, now)
	}
	c := clients["178.197.1.2:40001"]
	c.SentTo = 10
	in := linkreport.Report{Name: "wifi", Sent: 3, Received: 9, Dropped: 1}
	if handleClientDatagram(linkreport.Encode(in), addr, now.Add(2*time.Second)) {
		t.Fatal("a report was forwarded")
	}
	s := c.report
	if s == nil || s.Report != in || s.ServerSentTo != 10 || s.ServerReceivedFrom != 3 {
		t.Fatalf("sample: %+v", s)
	}
	if c.ReceivedFrom != 3 {
		t.Fatalf("the report was counted as data: ReceivedFrom=%d", c.ReceivedFrom)
	}
	if c.Last != 1002 {
		t.Fatalf("a report from a live address must refresh Last, got %d", c.Last)
	}
}

func TestAMalformedReportIsDroppedNotForwarded(t *testing.T) {
	resetClients()
	handleClientDatagram([]byte{4, 0, 0, 0}, addr, time.Now())
	if handleClientDatagram([]byte{linkreport.Magic, 99}, addr, time.Now()) {
		t.Fatal("a malformed report was forwarded")
	}
	if clients["178.197.1.2:40001"].report != nil {
		t.Fatal("a malformed report was stored")
	}
}
