package main

import (
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/porech/engarde/v2/internal/linkreport"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type config struct {
	Server serverConfig `yaml:"server"`
}

type serverConfig struct {
	Description   string        `yaml:"description"`
	ListenAddr    string        `yaml:"listenAddr"`
	DstAddr       string        `yaml:"dstAddr"`
	WriteTimeout  time.Duration `yaml:"writeTimeout"`
	ClientTimeout int64         `yaml:"clientTimeout"`
	WebManager    struct {
		ListenAddr string `yaml:"listenAddr"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
	} `yaml:"webManager"`
}

// ConnectedClient contains the information about a client: one address the
// laptop's links send from. The 64-bit fields come first so their atomic
// access stays 8-byte aligned on 32-bit builds (mips, arm).
type ConnectedClient struct {
	Last int64 // unix seconds of the last datagram from Addr; atomic
	// SentTo/ReceivedFrom count data datagrams written to and read from Addr,
	// and the *Bytes pair their payload; link reports are never counted.
	SentTo            uint64
	ReceivedFrom      uint64
	SentToBytes       uint64
	ReceivedFromBytes uint64
	Addr              *net.UDPAddr
	reportMu          sync.Mutex
	report            *linkSample
}

// linkSample is the latest report from the client link behind an address,
// paired with this server's own counters for that address at the instant it
// arrived — both halves of a delivery ratio sampled at the same moment.
type linkSample struct {
	linkreport.Report
	ServerSentTo       uint64
	ServerReceivedFrom uint64
	At                 int64 // unix milliseconds
}

var clients map[string]*ConnectedClient
var clientsMutex *sync.RWMutex
var srConfig serverConfig

// Version is passed by the compiler
var Version = "UNOFFICIAL BUILD"

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatal(msg+" | ", err)
	}
}

func getClientByAddr(addr *net.UDPAddr) *ConnectedClient {
	for _, client := range clients {
		if string(client.Addr.IP) == string(addr.IP) && client.Addr.Port == addr.Port {
			return client
		}
	}
	return nil
}

func printVersion() {
	if Version != "" {
		print("engarde-server ver. " + Version + "\r\n")
	}
}

func main() {
	var genconfig config
	var configName string
	if len(os.Args) > 1 {
		configName = os.Args[1]
	} else {
		configName = "engarde.yml"
	}

	printVersion()

	// If flag is -v, exit after printing version
	if configName == "-v" {
		return
	}

	yamlFile, err := os.ReadFile(configName)
	handleErr(err, "Reading config file "+configName+" failed")
	err = yaml.Unmarshal(yamlFile, &genconfig)
	handleErr(err, "Parsing config file failed")
	srConfig = genconfig.Server
	if srConfig.Description != "" {
		log.Info(srConfig.Description)
	}

	if srConfig.ListenAddr == "" {
		log.Fatal("No listenAddr specified.")
	}

	if srConfig.DstAddr == "" {
		log.Fatal("No dstAddr specified.")
	}
	if srConfig.ClientTimeout == 0 {
		srConfig.ClientTimeout = 30
	}
	if srConfig.WriteTimeout == 0 {
		srConfig.WriteTimeout = 10
	}

	clients = make(map[string]*ConnectedClient)
	clientsMutex = &sync.RWMutex{}

	WireguardAddr, err := net.ResolveUDPAddr("udp4", srConfig.DstAddr)
	handleErr(err, "Cannot resolve destination address")
	WireguardSource, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	handleErr(err, "Cannot resolve listen address")
	WireguardSocket, err := net.ListenUDP("udp", WireguardSource)
	handleErr(err, "Cannot initialize Wireguard socket")

	ClientsListenAddr, err := net.ResolveUDPAddr("udp4", srConfig.ListenAddr)
	handleErr(err, "Cannot resolve listen address")
	ClientSocket, err := net.ListenUDP("udp", ClientsListenAddr)
	handleErr(err, "Cannot create listen socket")
	log.Info("Listening on " + srConfig.ListenAddr)

	if srConfig.WebManager.ListenAddr != "" {
		go webserver(srConfig.WebManager.ListenAddr, srConfig.WebManager.Username, srConfig.WebManager.Password)
	}
	go receiveFromWireguard(WireguardSocket, ClientSocket)
	receiveFromClient(ClientSocket, WireguardSocket, WireguardAddr)
}

// handleClientDatagram books one datagram from a client address and says
// whether it is WireGuard traffic to forward. A link report is consumed here
// and never forwarded. It annotates an address that data already registered
// and never registers one itself: any UDP source can reach this port, and an
// address in the table receives every downstream copy.
func handleClientDatagram(buf []byte, srcAddr *net.UDPAddr, now time.Time) bool {
	srcAddrS := srcAddr.IP.String() + ":" + strconv.Itoa(srcAddr.Port)
	clientsMutex.RLock()
	client, exists := clients[srcAddrS]
	clientsMutex.RUnlock()

	if linkreport.IsReport(buf) {
		if !exists {
			return false
		}
		r, err := linkreport.Decode(buf)
		if err != nil {
			return false
		}
		atomic.StoreInt64(&client.Last, now.Unix())
		sample := &linkSample{
			Report:             r,
			ServerSentTo:       atomic.LoadUint64(&client.SentTo),
			ServerReceivedFrom: atomic.LoadUint64(&client.ReceivedFrom),
			At:                 now.UnixNano() / int64(time.Millisecond),
		}
		client.reportMu.Lock()
		client.report = sample
		client.reportMu.Unlock()
		return false
	}

	if exists {
		atomic.StoreInt64(&client.Last, now.Unix())
	} else {
		log.Info("New client connected: '" + srcAddrS + "'")
		client = &ConnectedClient{Addr: srcAddr, Last: now.Unix()}
		clientsMutex.Lock()
		clients[srcAddrS] = client
		clientsMutex.Unlock()
	}
	atomic.AddUint64(&client.ReceivedFrom, 1)
	atomic.AddUint64(&client.ReceivedFromBytes, uint64(len(buf)))
	return true
}

func receiveFromClient(socket, wgSocket *net.UDPConn, wgAddr *net.UDPAddr) {
	buffer := make([]byte, 1500)
	for {
		n, srcAddr, err := socket.ReadFromUDP(buffer)
		if err != nil {
			log.Warn("Error reading from client")
			continue
		}
		if !handleClientDatagram(buffer[:n], srcAddr, time.Now()) {
			continue
		}
		_, err = wgSocket.WriteToUDP(buffer[:n], wgAddr)
		if err != nil {
			log.Warn("Error writing to WireGuard")
		}
	}
}

func receiveFromWireguard(wgSocket, socket *net.UDPConn) {
	buffer := make([]byte, 1500)
	var n int
	var client *ConnectedClient
	var currentTime int64
	var clientAddr string
	var err error
	var toDelete []string
	for {
		n, _, err = wgSocket.ReadFromUDP(buffer)
		if err != nil {
			log.Warn("Error reading from WireGuard")
			continue
		}
		currentTime = time.Now().Unix()
		clientsMutex.RLock()
		for clientAddr, client = range clients {
			if atomic.LoadInt64(&client.Last) > currentTime-srConfig.ClientTimeout {
				if srConfig.WriteTimeout > 0 {
					err = socket.SetWriteDeadline(time.Now().Add(srConfig.WriteTimeout * time.Millisecond))
					if err != nil {
						log.WithError(err).Warn("Error setting write deadline to " + srConfig.WriteTimeout.String())
					}
				}
				_, err = socket.WriteToUDP(buffer[:n], client.Addr)
				if err != nil {
					log.Warn("Error writing to client '" + clientAddr + "', terminating it")
					toDelete = append(toDelete, clientAddr)
				} else {
					atomic.AddUint64(&client.SentTo, 1)
					atomic.AddUint64(&client.SentToBytes, uint64(n))
				}
			} else {
				log.Info("Client '" + clientAddr + "' timed out")
				toDelete = append(toDelete, clientAddr)
			}
		}
		clientsMutex.RUnlock()
		clientsMutex.Lock()
		for _, clientAddr = range toDelete {
			delete(clients, clientAddr)
		}
		clientsMutex.Unlock()
		toDelete = toDelete[:0]
	}
}
