package algnone

type signingMethodNone struct {
	alg string
}

func (m *signingMethodNone) SetAlg(alg string) {
	m.alg = alg
}

func (m *signingMethodNone) Alg() string {
	return m.alg
}
func (m *signingMethodNone) Verify(signingString string, sig []byte, key interface{}) (err error) {
	return nil
}
func (m *signingMethodNone) Sign(signingString string, key interface{}) ([]byte, error) {
	return []byte{}, nil
}
