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

			switch jobEntities.SupportedOSSProvider(msg.GetProvider()) {
			case jobEntities.OSS_PROVIDER_VIRUS_TOTAL:
				routines[0].input <- msg
			case jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE:
				routines[1].input <- msg
			case jobEntities.OSS_PROVIDER_SHODAN:
				routines[2].input <- msg
			case jobEntities.OSS_PROVIDER_CROWD_SEC:
				routines[3].input <- msg
			case jobEntities.OSS_PROVIDER_IP_WHO_IS:
				routines[4].input <- msg
			}
		}
	}

	wg.Wait() // waiting for all transactions to end
}

func (h *OSSJobHandler) createStartRoutines(ctx context.Context, wg *sync.WaitGroup) [5]ossProviderRoutine {
	vtCh := make(chan *protoServices.TargetAuditReport, 100)
	ipqsCh := make(chan *protoServices.TargetAuditReport, 100)
	shdCh := make(chan *protoServices.TargetAuditReport, 100)
	csCh := make(chan *protoServices.TargetAuditReport, 100)
	ipwhCh := make(chan *protoServices.TargetAuditReport, 100)

	vtRoutine := ossProviderRoutine{
		repo:      h.repo,                                   // repo to save records to database
		input:     vtCh,                                     // passing audit reports from agent
		wg:        wg,                                       // required to wait for all transactions to end
		ctx:       ctx,                                      // passing context to finish underlying routines
		agentUUID: h.agent.UUID,                             // agent uuid
		jobUUID:   h.job.Meta.UUID,                          // job uuid
		scanType:  uint64(networkEntities.SCAN_TYPE_OSS_VT), // predefined open source scan type
	}

	ipqsRoutine := ossProviderRoutine{
		repo:      h.repo,
		input:     ipqsCh,
		wg:        wg,
		ctx:       ctx,
		agentUUID: h.agent.UUID,
		jobUUID:   h.job.Meta.UUID,
		scanType:  uint64(networkEntities.SCAN_TYPE_OSS_IPQS),
	}

	shdRoutine := ossProviderRoutine{
		repo:      h.repo,
		input:     shdCh,
		wg:        wg,
		ctx:       ctx,
		agentUUID: h.agent.UUID,
		jobUUID:   h.job.Meta.UUID,
		scanType:  uint64(networkEntities.SCAN_TYPE_OSS_SHD),
	}

	csRoutine := ossProviderRoutine{
		repo:      h.repo,
		input:     csCh,
		wg:        wg,
		ctx:       ctx,
		agentUUID: h.agent.UUID,
		jobUUID:   h.job.Meta.UUID,
		scanType:  uint64(networkEntities.SCAN_TYPE_OSS_CS),
	}

	ipwhRoutine := ossProviderRoutine{
		repo:      h.repo,
		input:     ipwhCh,
		wg:        wg,
		ctx:       ctx,
		agentUUID: h.agent.UUID,
		jobUUID:   h.job.Meta.UUID,
		scanType:  uint64(networkEntities.SCAN_TYPE_OSS_IPWH),
	}

	// staring all routines
	go vtRoutine.start()
	go ipqsRoutine.start()
	go shdRoutine.start()
	go csRoutine.start()
	go ipwhRoutine.start()

	return [5]ossProviderRoutine{vtRoutine, ipqsRoutine, shdRoutine, csRoutine, ipwhRoutine}
}

type ossProviderRoutine struct {
	repo  core.INetworkNodesRepo
	input chan *protoServices.TargetAuditReport
	wg    *sync.WaitGroup
	ctx   context.Context

	agentUUID *pgtype.UUID
	jobUUID   *pgtype.UUID

	scanType uint64
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
			err = r.repo.CreateNetworkNodeWithIdentity(networkEntities.NetworkNodeScan{
				IsComplete: true,
				JobUUID:    r.jobUUID,
				ScanTypeID: r.scanType,
				Data:       msg.Content,
			}, jobEntities.Target{
				Host: t.Host,
				Type: jobEntities.TargetType(t.Type),
			})
		} else {
			c, _ := json.Marshal(errorScanData{
				ErrorMessage: string(msg.Content),
			})

			err = r.repo.CreateNetworkNodeWithIdentity(networkEntities.NetworkNodeScan{
				IsComplete: true,
				JobUUID:    r.jobUUID,
				ScanTypeID: r.scanType,
				Data:       c,
			}, jobEntities.Target{
				Host: t.Host,
				Type: jobEntities.TargetType(t.Type),
			})
		}

		if err != nil {
			slog.Error(err.Error()) // TODO: add job handling logger
		}

		r.wg.Done()
	}
}

type errorScanData struct {
	ErrorMessage string `json:"error_message"`
}
