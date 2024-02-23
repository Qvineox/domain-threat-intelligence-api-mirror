package jobEntities

type Job struct {
	Meta    Metadata `json:"Meta"`
	Payload Payload  `json:"Payload"`
}
