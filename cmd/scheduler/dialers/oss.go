package dialers

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"encoding/json"
	"github.com/jackc/pgtype"
	"log/slog"
	"sync"
)

type OSSJobHandler struct {
	repo core.INetworkNodesRepo

	scans chan *protoServices.TargetAuditReport

	agent *agentEntities.ScanAgent
	job   *jobEntities.Job
}

func NewOSSJobHandler(a *agentEntities.ScanAgent, j *jobEntities.Job, r core.INetworkNodesRepo, ch chan *protoServices.TargetAuditReport) OSSJobHandler {
	return OSSJobHandler{agent: a, job: j, repo: r, scans: ch}
}

func (h *OSSJobHandler) Start(ctx context.Context, wg *sync.WaitGroup) {
	routines := h.createStartRoutines(ctx, wg)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case msg, ok := <-h.scans:
			if !ok {
				continue
			}

			switch networkEntities.ScanType(msg.GetScanType()) / 100 {
			case 1:
				routines[0].input <- msg
			case 2:
				routines[1].input <- msg
			case 3:
				routines[2].input <- msg
			case 4:
				routines[3].input <- msg
			case 5:
				routines[4].input <- msg
			default:
				slog.Warn("unsupported scan type message received")
			}
		}
	}

	wg.Wait() // waiting for all transactions to end
}

func (h *OSSJobHandler) createStartRoutines(ctx context.Context, wg *sync.WaitGroup) [5]ossProviderRoutine {
	routines := [5]ossProviderRoutine{}

	for i := 0; i < 5; i++ {
		ch := make(chan *protoServices.TargetAuditReport, 100)

		routines[i] = ossProviderRoutine{
			repo:      h.repo,          // repo to save records to database
			input:     ch,              // passing audit reports from agent
			wg:        wg,              // required to wait for all transactions to end
			ctx:       ctx,             // passing context to finish underlying routines
			agentUUID: h.agent.UUID,    // agent uuid
			jobUUID:   h.job.Meta.UUID, // job uuid
		}

		// staring all routines
		go routines[i].start()
	}

	return routines
}

type ossProviderRoutine struct {
	repo  core.INetworkNodesRepo
	input chan *protoServices.TargetAuditReport
	wg    *sync.WaitGroup
	ctx   context.Context

	agentUUID *pgtype.UUID
	jobUUID   *pgtype.UUID
}

func (r *ossProviderRoutine) start() {
	for {
		msg, ok := <-r.input
		if !ok {
			break
		}

		t := msg.GetTarget()

		var err error

		if msg.IsSuccessful {
			scan := networkEntities.NetworkNodeScan{
				IsComplete: true,
				JobUUID:    r.jobUUID,
				ScanTypeID: uint64(msg.GetScanType()),
			}

			err = scan.ProcessCollectedData(msg.GetContent())
			if err != nil {
				slog.Warn("failed to process scan data, saved without processing: " + err.Error())
			}

			target := jobEntities.Target{
				Host: t.Host,
				Type: jobEntities.TargetType(t.Type),
			}

			err = r.repo.CreateNetworkNodeWithIdentity(scan, target)
		} else {
			c, _ := json.Marshal(errorScanData{
				ErrorMessage: string(msg.Content),
			})

			err = r.repo.CreateNetworkNodeWithIdentity(networkEntities.NetworkNodeScan{
				IsComplete: false,
				JobUUID:    r.jobUUID,
				ScanTypeID: uint64(msg.GetScanType()),
				Data:       c,
			}, jobEntities.Target{
				Host: t.Host,
				Type: jobEntities.TargetType(t.Type),
			})
		}

		if err != nil {
			slog.Error("failed to save network scan record: " + err.Error())
		}

		r.wg.Done()
	}
}

type errorScanData struct {
	ErrorMessage string `json:"error_message"`
}
