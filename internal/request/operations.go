package request

type Operations []*Operation

func (o Operations) Len() int      { return len(o) }
func (o Operations) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Operations) Less(i, j int) bool {
	if o[i].URL == o[j].URL {
		return o[i].Method < o[j].Method
	}

	return o[i].URL.String() < o[j].URL.String()
}

func (o Operations) GetByID(id string) *Operation {
	for _, op := range o {
		if op.GetID() == id {
			return op
		}
	}
	return nil
}
