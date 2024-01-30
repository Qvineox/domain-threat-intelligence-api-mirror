package naumen

import (
	"bytes"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"domain_threat_intelligence_api/configs"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ServiceDeskClient struct {
	repo       core.IServiceDeskRepo
	httpClient http.Client

	dynamic *configs.DynamicConfig
}

func NewServiceDeskClient(repo core.IServiceDeskRepo, dynamicConfig *configs.DynamicConfig) *ServiceDeskClient {
	client := ServiceDeskClient{
		repo:    repo,
		dynamic: dynamicConfig,
		httpClient: http.Client{
			Timeout: 30 * time.Second,
		},
	}

	if !client.IsAvailable() {
		slog.Warn("required config values not provided. naumen service desk integration not available.")
	}

	return &client
}

func (s *ServiceDeskClient) IsAvailable() bool {
	_, err := s.dynamic.GetNaumenURL()
	if err != nil {
		return false
	}

	_, _, _, err = s.dynamic.GetNaumenCredentials()
	if err != nil {
		return false
	}

	_, _, _, err = s.dynamic.GetNaumenBlacklistService()
	if err != nil {
		return false
	}

	return true
}

func (s *ServiceDeskClient) RetrieveTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error) {
	return s.repo.SelectTicketsByFilter(filter)
}

func (s *ServiceDeskClient) DeleteTicket(id uint64) error {
	return s.repo.DeleteTicket(id)
}

func (s *ServiceDeskClient) SendBlacklistedHosts(hosts []blacklistEntities.BlacklistedHost) (ticket serviceDeskEntities.ServiceDeskTicket, err error) {
	ticket = serviceDeskEntities.ServiceDeskTicket{
		System: "naumen",
	}

	var requestAttributes struct {
		SubjectTicket    string `json:"subjectTicket,omitempty"`
		DescriptionInRTF string `json:"descriptionInRTF,omitempty"`
		Agreement        string `json:"agreement,omitempty"`
		Service          string `json:"service,omitempty"`
		ClientEmployee   string `json:"clientEmployee,omitempty"`
		ClientOU         string `json:"clientOU,omitempty"`
	}

	// get service configuration
	url, err := s.dynamic.GetNaumenURL()
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	key, emp, ou, err := s.dynamic.GetNaumenCredentials()
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	ag, slm, callType, err := s.dynamic.GetNaumenBlacklistService()
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	requestAttributes.SubjectTicket = "Заблокировать доступ к/от указанных адресов. Добавить в черный список ФинЦЕРТ."

	description, err := s.buildHostsDescription(hosts)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, errors.New("failed to create description: " + err.Error())
	}

	requestAttributes.DescriptionInRTF = description
	requestAttributes.Agreement = fmt.Sprintf("agreement$%d", ag)
	requestAttributes.Service = fmt.Sprintf("slmService$%d", slm)
	requestAttributes.ClientEmployee = fmt.Sprintf("employee$%s", emp)
	requestAttributes.ClientOU = fmt.Sprintf("ou$%s", ou)

	bytes_, err := json.Marshal(requestAttributes)
	if err != nil {
		slog.Error("failed to marshal service desk request: " + err.Error())
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	url_ := fmt.Sprintf("%s/sd/services/rest/create-m2m/serviceCall$%s?accessKey=%s",
		url,
		callType,
		key)

	url_ = strings.ReplaceAll(url_, "\"", "'")
	request, err := http.NewRequest("POST", url_, bytes.NewBuffer(bytes_))
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	response, err := s.httpClient.Do(request)
	if err != nil || response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized {
		if response != nil {
			text, err_ := io.ReadAll(response.Body)
			if err_ != nil {
				return serviceDeskEntities.ServiceDeskTicket{}, err
			} else {
				return serviceDeskEntities.ServiceDeskTicket{}, errors.New(string(text))
			}
		} else if err != nil {
			return serviceDeskEntities.ServiceDeskTicket{}, err
		} else {
			return serviceDeskEntities.ServiceDeskTicket{}, errors.New("naumen request error")
		}
	} else {
		var responseBody requestCreateResponseBody

		err = json.NewDecoder(response.Body).Decode(&responseBody)
		if err != nil {
			return serviceDeskEntities.ServiceDeskTicket{}, err
		} else if len(responseBody.UUID) == 0 {
			return serviceDeskEntities.ServiceDeskTicket{}, errors.New("missing naumen uuid")
		} else {
			ticket.TicketID = responseBody.UUID
			slog.Info("sent naumen service desk ticket: " + ticket.TicketID)

			marshalTicket, err := json.Marshal(ticket)
			if err != nil {
				slog.Error("failed to scan naumen response body: " + err.Error())
			} else {
				ticket.Data = marshalTicket
			}
		}
	}

	file, err := s.buildHostsFile(hosts)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	err = s.appendFile(ticket.TicketID, file.Name())
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, errors.New("failed to append file: " + err.Error())
	} else {
		slog.Info("added file to naumen service desk ticket: " + ticket.TicketID)
		_ = os.Remove(file.Name())
	}

	ticket, err = s.repo.SaveTicket(ticket)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	return ticket, nil
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

func (s *ServiceDeskClient) buildHostsDescription(hosts []blacklistEntities.BlacklistedHost) (string, error) {
	types, err := s.dynamic.GetNaumenBlacklistTypes()
	if err != nil {
		return "", err
	}

	var stats = struct {
		total  int
		ip     int
		domain int
		url    int
		email  int
	}{}

	for _, v := range types {
		switch v {
		case "ip":
			for _, h := range hosts {
				if h.Type == "ip" {
					stats.ip++
				}
			}
		case "domain":
			for _, h := range hosts {
				if h.Type == "domain" {
					stats.domain++
				}
			}
		case "url":
			for _, h := range hosts {
				if h.Type == "url" {
					stats.url++
				}
			}
		case "email":
			for _, h := range hosts {
				if h.Type == "email" {
					stats.email++
				}
			}
		}
	}

	var desc = "<style>table{width:100%;border-collapse: collapse;} thead{background-color:#7f96b9; font-weight:bold;} td{border: 1px solid; text-align: center;}</style>"

	desc += "<p>Добрый день!</p>"
	desc += fmt.Sprintf("<p>От ФинЦЕРТ'а поступило %d новых адресов для блокировки. Адреса указаны в приложенном файле.</p>", stats.ip+stats.domain+stats.url+stats.email)

	desc += "<table>"
	desc += "<thead><tr><td>Тип хоста</td><td>Количество</td></tr></thead>"
	desc += "<tbody>"

	if stats.ip > 0 {
		desc += fmt.Sprintf("<tr><td>IP адреса</td><td>%d</td></tr>", stats.ip)
	}

	if stats.domain > 0 {
		desc += fmt.Sprintf("<tr><td>Домены</td><td>%d</td></tr>", stats.domain)
	}

	if stats.url > 0 {
		desc += fmt.Sprintf("<tr><td>URL</td><td>%d</td></tr>", stats.url)
	}

	if stats.email > 0 {
		desc += fmt.Sprintf("<tr><td>Почтовые адреса</td><td>%d</td></tr>", stats.email)
	}

	desc += "</tbody></table>"

	desc += "<br/>"
	desc += "<i>Данная заявка сгенерирована роботом. В случае обнаружения ошибок/некорректных данных, просьба проинформировать заявителя.</i>"

	return desc, nil
}

func (s *ServiceDeskClient) buildHostsFile(hosts []blacklistEntities.BlacklistedHost) (*os.File, error) {
	types, err := s.dynamic.GetNaumenBlacklistTypes()
	if err != nil {
		return nil, err
	}

	pattern := fmt.Sprintf("hosts_%s.*.txt", time.Now().Format("02_01_06"))
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, errors.New("failed to create temporary file: " + err.Error())
	}

	var writeValue string

	for _, v := range types {
		switch v {
		case "ip":
			for _, h := range hosts {
				if h.Type == "ip" {
					writeValue += fmt.Sprintf("%s\n", h.Host)
				}
			}
			writeValue += "\n"
		case "domain":
			for _, h := range hosts {
				if h.Type == "domain" {
					writeValue += fmt.Sprintf("%s\n", h.Host)
				}
			}
			writeValue += "\n"
		case "url":
			for _, h := range hosts {
				if h.Type == "url" {
					writeValue += fmt.Sprintf("%s\n", h.Host)
				}
			}
			writeValue += "\n"
		case "email":
			for _, h := range hosts {
				if h.Type == "email" {
					writeValue += fmt.Sprintf("%s\n", h.Host)
				}
			}
			writeValue += "\n"
		}
	}

	_, err = file.Write([]byte(writeValue))
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (s *ServiceDeskClient) appendFile(ticketID string, filePath string) error {
	url, err := s.dynamic.GetNaumenURL()
	if err != nil {
		return err
	}

	key, _, _, err := s.dynamic.GetNaumenCredentials()
	if err != nil {
		return err
	}

	file, _ := os.Open(filePath)
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", filepath.Base(file.Name()))

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	writer.Close()

	fileAppendURL := fmt.Sprintf("%s/sd/services/rest/add-file/%s?accessKey=%s",
		url,
		ticketID,
		key)

	r, _ := http.NewRequest("POST", fileAppendURL, body)
	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}

	response, err := client.Do(r)
	if err != nil {
		return err
	} else if response != nil && (response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized) {
		return errors.New("failed with status: " + response.Status)
	}

	return nil
}
