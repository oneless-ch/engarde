package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/porech/engarde/v2/internal/assets"
	log "github.com/sirupsen/logrus"
)

type webSocket struct {
	Address           string   `json:"address"`
	Last              *int64   `json:"last"`
	SentTo            uint64   `json:"sentTo"`
	ReceivedFrom      uint64   `json:"receivedFrom"`
	SentToBytes       uint64   `json:"sentToBytes"`
	ReceivedFromBytes uint64   `json:"receivedFromBytes"`
	Link              *webLink `json:"link,omitempty"`
}

// webLink is the latest link report for an address, with this server's
// counters as they stood when it arrived (see linkSample).
type webLink struct {
	Name               string `json:"name"`
	ClientSent         uint64 `json:"clientSent"`
	ClientReceived     uint64 `json:"clientReceived"`
	ClientDropped      uint64 `json:"clientDropped"`
	ServerSentTo       uint64 `json:"serverSentTo"`
	ServerReceivedFrom uint64 `json:"serverReceivedFrom"`
	At                 int64  `json:"at"` // unix milliseconds
}

func webBasicAuth(handler http.HandlerFunc, username, password, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username != "" && password != "" {
			user, pass, ok := r.BasicAuth()

			if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				w.WriteHeader(401)
				w.Write([]byte("Unauthorized.\n"))
				return
			}
		}
		handler(w, r)
	}
}

func webHandleFileServer(webFS fs.FS) http.HandlerFunc {
	fs := http.FileServer(http.FS(webFS))
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			index, err := webFS.Open("index.html")
			if err != nil {
				http.NotFound(w, req)
				return
			}
			defer index.Close()
			content, err := io.ReadAll(index)
			if err != nil {
				http.NotFound(w, req)
				return
			}
			w.WriteHeader(200)
			w.Write(content)
			return
		}
		fs.ServeHTTP(w, req)
	}
}

func webGetList(w http.ResponseWriter, r *http.Request) {
	rspSockets := []webSocket{}
	// The table is written by the client reader; read it under the lock.
	clientsMutex.RLock()
	for address, client := range clients {
		lastSeen := atomic.LoadInt64(&client.Last)
		last := time.Now().Unix() - lastSeen
		rspSocket := webSocket{
			Address:           address,
			SentTo:            atomic.LoadUint64(&client.SentTo),
			ReceivedFrom:      atomic.LoadUint64(&client.ReceivedFrom),
			SentToBytes:       atomic.LoadUint64(&client.SentToBytes),
			ReceivedFromBytes: atomic.LoadUint64(&client.ReceivedFromBytes),
		}
		if lastSeen > 0 {
			rspSocket.Last = &last
		}
		client.reportMu.Lock()
		if s := client.report; s != nil {
			rspSocket.Link = &webLink{
				Name: s.Name, ClientSent: s.Sent, ClientReceived: s.Received,
				ClientDropped: s.Dropped, ServerSentTo: s.ServerSentTo,
				ServerReceivedFrom: s.ServerReceivedFrom, At: s.At,
			}
		}
		client.reportMu.Unlock()
		rspSockets = append(rspSockets, rspSocket)
	}
	clientsMutex.RUnlock()

	rspObject := struct {
		Type          string      `json:"type"`
		Version       string      `json:"version"`
		Description   string      `json:"description"`
		ListenAddress string      `json:"listenAddress"`
		DstAddress    string      `json:"dstAddress"`
		Sockets       []webSocket `json:"sockets"`
	}{"server", Version, srConfig.Description, srConfig.ListenAddr, srConfig.DstAddr, rspSockets}
	rspJSON, err := json.Marshal(rspObject)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Internal server error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(rspJSON)
}

func webserver(listenAddr, username, password string) {
	for {
		realm := "engarde"
		webFS := assets.GetWebFS()
		http.HandleFunc("/", webBasicAuth(webHandleFileServer(webFS), username, password, realm))
		http.HandleFunc("/api/v1/get-list", NoCache(webBasicAuth(webGetList, username, password, realm)))
		log.Info("Management webserver listening on " + listenAddr)
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			log.Error(err)
			time.Sleep(1 * time.Second)
		}
	}
}
