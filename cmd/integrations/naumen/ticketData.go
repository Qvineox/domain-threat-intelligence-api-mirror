package naumen

import "domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"

type ticketData struct {
	UUID               string            `json:"UUID"`
	TicketNumber       uint              `json:"TicketNumber"`
	TicketTitle        string            `json:"TicketTitle"`
	SubjectTicket      string            `json:"SubjectTicket"`
	ClientEmployeeUUID string            `json:"ClientEmployeeUUID"`
	ClientGroupUUID    string            `json:"ClientGroupUUID"`
	ServiceUUID        string            `json:"ServiceUUID"`
	AgreementTypeUUID  string            `json:"AgreementTypeUUID"`
	Payload            ticketDataPayload `json:"Payload"`
}

func newTicketDataFromResponse(r requestCreateResponseBody) ticketData {
	return ticketData{
		UUID:               r.UUID,
		TicketNumber:       r.Number,
		TicketTitle:        r.Title,
		SubjectTicket:      r.SubjectTicket,
		ClientEmployeeUUID: r.ClientEmployee.UUID,
		ClientGroupUUID:    r.ClientOU.UUID,
		ServiceUUID:        r.Service.UUID,
		AgreementTypeUUID:  r.Agreement.UUID,
	}
}

func (t *ticketData) FillPayload(hosts []blacklistEntities.BlacklistedHost) {
	var i, d, u, e []string

	for _, h := range hosts {
		switch h.Type {
		case "ip":
			i = append(i, h.Host)
		case "domain":
			d = append(d, h.Host)
		case "url":
			u = append(u, h.Host)
		case "email":
			e = append(e, h.Host)
		}
	}

	t.Payload = ticketDataPayload{
		IPs:     i,
		Domains: d,
		URLs:    u,
		Emails:  e,
	}
}

type ticketDataPayload struct {
	IPs     []string `json:"IPs,omitempty"`
	Domains []string `json:"Domains,omitempty"`
	URLs    []string `json:"URLs,omitempty"`
	Emails  []string `json:"Emails,omitempty"`
}

type requestCreateResponseBody struct {
	Agreement struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"agreement"`

	// RespTe - request responsible team
	RespTe struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"resp_te"`
	Responsible struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"responsible"`

	Registrar struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"registrar"`
	ClientEmployee struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"clientEmployee"`
	ClientOU struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"clientOU"`

	Service struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
	} `json:"service"`
	TypeService struct {
		UUID      string `json:"UUID"`
		Title     string `json:"title"`
		MetaClass string `json:"metaClass"`
		Code      string `json:"code"`
	} `json:"typeService"`

	Title  string `json:"title"` // Title - number of a request (example, IT-1234567)
	Number uint   `json:"number"`

	SubjectTicket    string `json:"subjectTicket"`    // SubjectTicket - main title of a request (example, "Блокирование УЗ - NSD")
	DescriptionInRTF string `json:"descriptionInRTF"` // DescriptionInRTF - request description

	UUID string `json:"UUID"`
}
