package socket

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/scheduler"
	"fmt"
	"github.com/gorilla/websocket"
	"log/slog"
	"time"
)

type QueueNotifier struct {
	Conn         *websocket.Conn
	jobScheduler *scheduler.Scheduler

	send chan [3][]*jobEntities.Job

	pollingRateMS time.Duration
}

func NewQueueNotifier(conn *websocket.Conn, pr time.Duration, jobScheduler *scheduler.Scheduler) *QueueNotifier {
	return &QueueNotifier{Conn: conn, pollingRateMS: pr, send: make(chan [3][]*jobEntities.Job, 256), jobScheduler: jobScheduler}
}

func (c *QueueNotifier) Write() {
	ticker := time.NewTicker(c.pollingRateMS * time.Millisecond)

	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			} else {
				err := c.Conn.WriteJSON(message)
				if err != nil {
					fmt.Println("Error: ", err)
					break
				}
			}
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

			jobs := c.jobScheduler.GetAllJobs()

			err := c.Conn.WriteJSON(queuedJobs{
				Queued: jobs[0],
				Sent:   jobs[1],
				Latest: jobs[2],
			})
			if err != nil {
				slog.Warn("failed to encode websocket message: " + err.Error())
				return
			}
		}

	}
}

func (c *QueueNotifier) Close() {
	close(c.send)
}

type queuedJobs struct {
	Queued []*jobEntities.Job `json:"queued"`
	Sent   []*jobEntities.Job `json:"sent"`
	Latest []*jobEntities.Job `json:"latest"`
}
