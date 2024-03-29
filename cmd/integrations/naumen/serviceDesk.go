package naumen

import (
	"bytes"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type ServiceDeskClient struct {
	repo       core.IServiceDeskRepo
	httpClient http.Client

	dynamicConfig INaumenDynamicConfig
}

type INaumenDynamicConfig interface {
	IsNaumenEnabled() bool
	GetNaumenCredentials() (url, key string, uID, gID uint64, err error)
	GetBlacklistServiceConfig() (aID, slm uint64, callType string, types []string, err error)
	SetNaumenConfig(enabled bool, host, key string, uID, gID uint64) (err error)
	SetNaumenBlacklistServiceConfig(aID, slm uint64, callType string, types []string) (err error)
}

func NewServiceDeskClient(repo core.IServiceDeskRepo, dynamicConfig INaumenDynamicConfig) *ServiceDeskClient {
	client := ServiceDeskClient{
		repo:          repo,
		dynamicConfig: dynamicConfig,
		httpClient: http.Client{
			Timeout: 30 * time.Second,
		},
	}

	if !client.IsAvailable() {
		slog.Warn("required config values not provided. naumen service desk integration not available.")
	} else {
		slog.Info("naumen service desk integration configured successfully.")
	}

	return &client
}

func (s *ServiceDeskClient) IsAvailable() bool {
	return s.dynamicConfig.IsNaumenEnabled()
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
	url, key, emp, ou, err := s.dynamicConfig.GetNaumenCredentials()
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	// filter hosts to send by preconfigured types
	ag, slm, callType, types, err := s.dynamicConfig.GetBlacklistServiceConfig()
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	var filteredHosts []blacklistEntities.BlacklistedHost
	var stats = blacklistStats{}

	for _, h := range hosts {
		if slices.Contains(types, h.Type) {
			switch h.Type {
			case "ip":
				stats.ip++
			case "domain":
				stats.domain++
			case "url":
				stats.url++
			case "email":
				stats.email++
			default:
				slog.Warn("unsupported host type found during ticket stats count: " + h.Type)
				continue
			}

			filteredHosts = append(filteredHosts, h)
		}
	}

	requestAttributes.SubjectTicket = "Заблокировать доступ к/от указанных адресов. Добавить в черный список ФинЦЕРТ."

	description, err := s.buildHostsDescription(stats)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, errors.New("failed to create description: " + err.Error())
	}

	requestAttributes.DescriptionInRTF = description
	requestAttributes.Agreement = fmt.Sprintf("agreement$%d", ag)
	requestAttributes.Service = fmt.Sprintf("slmService$%d", slm)
	requestAttributes.ClientEmployee = fmt.Sprintf("employee$%d", emp)
	requestAttributes.ClientOU = fmt.Sprintf("ou$%d", ou)

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
			data := newTicketDataFromResponse(responseBody)
			data.FillPayload(filteredHosts)

			slog.Info("sent naumen service desk ticket: " + ticket.TicketID)

			marshalTicket, err := json.Marshal(data)
			if err != nil {
				slog.Error("failed to scan naumen response body: " + err.Error())
			} else {
				ticket.Data = marshalTicket
			}
		}
	}

	file, err := s.buildHostsFile(filteredHosts)
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

type blacklistStats struct {
	total  int
	ip     int
	domain int
	url    int
	email  int
}

func (s *ServiceDeskClient) buildHostsDescription(stats blacklistStats) (string, error) {
	var desc = "<style>table{width:100%;border-collapse: collapse;} thead{background-color:#7f96b9; font-weight:bold;} td{border: 1px solid; text-align: center;}</style>"

	desc += "<p>Добрый день!</p>"
	desc += fmt.Sprintf("<p>От ФинЦЕРТ'а поступило %d новых адресов для блокировки. Адреса указаны в приложенном файле.</p>", stats.ip+stats.domain+stats.url+stats.email)
	desc += "<p>Прошу добавить в черный список ФинЦЕРТ. Также необходимо заблокировать данные адреса в ИС Qrator.</p>"

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
	pattern := fmt.Sprintf("hosts_%s.*.txt", time.Now().Format("02_01_06"))
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, errors.New("failed to create temporary file: " + err.Error())
	}

	var writeValue string
	for _, h := range hosts {
		writeValue += fmt.Sprintf("%s\n", h.Host)
	}

	_, err = file.Write([]byte(writeValue))
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (s *ServiceDeskClient) appendFile(ticketID string, filePath string) error {
	url, key, _, _, err := s.dynamicConfig.GetNaumenCredentials()
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
