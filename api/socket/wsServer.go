package socket

import (
	"domain_threat_intelligence_api/cmd/scheduler"
	"github.com/gorilla/websocket"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type WebSocketServer struct {
	server websocket.Upgrader

	jobScheduler *scheduler.Scheduler

	host string
	port uint64

	pollingRateMS time.Duration
}

func NewWebSocketServer(jobScheduler *scheduler.Scheduler, host string, port uint64, pr time.Duration) (*WebSocketServer, error) {
	s := &WebSocketServer{
		server: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		jobScheduler:  jobScheduler,
		host:          host,
		port:          port,
		pollingRateMS: pr,
	}

	http.HandleFunc("/ws/queue", s.handleQueueUpdates)
	return s, nil
}

func (s *WebSocketServer) Start(wg *sync.WaitGroup) {
	slog.Info("starting web socket server...")

	go func() {
		err := http.ListenAndServe(net.JoinHostPort(s.host, strconv.FormatUint(s.port, 10)), nil)
		if err != nil {
			slog.Error("failed to start web socket server: " + err.Error())
			panic(err)
		}
	}()

	wg.Done()
}

func (s *WebSocketServer) handleQueueUpdates(w http.ResponseWriter, r *http.Request) {
	conn, err := s.server.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("failed to establish websocket connection: " + err.Error())
	}

	ticker := time.NewTicker(s.pollingRateMS * time.Millisecond)

	defer conn.Close()
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(s.pollingRateMS * time.Millisecond / 2))
			err = conn.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				return
			}

			jobs := s.jobScheduler.GetAllJobs()

			err := conn.WriteJSON(jobs)
			if err != nil {
				slog.Warn("failed to encode websocket message: " + err.Error())
				return
			}
		}
	}
}
