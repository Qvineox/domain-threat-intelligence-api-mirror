package socket

import (
	"domain_threat_intelligence_api/cmd/scheduler"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"log/slog"
	"net/http"
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

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func NewWebSocketServer(path *gin.RouterGroup, jobScheduler *scheduler.Scheduler, pr time.Duration) {
	server := &WebSocketServer{
		jobScheduler:  jobScheduler,
		pollingRateMS: pr,
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	path.GET("/ws/queue", func(c *gin.Context) {
		server.serveWS(c)
	})
}

func (s *WebSocketServer) serveWS(ctx *gin.Context) {
	ws, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		slog.Error("failed to establish connection: " + err.Error())
		return
	}

	notifier := NewQueueNotifier(ws, s.pollingRateMS, s.jobScheduler)

	go notifier.Write()
}
