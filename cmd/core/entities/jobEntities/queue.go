package jobEntities

type Queue struct {
	limit uint64

	jobs []*Job
}
