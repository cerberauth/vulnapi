package jwt

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iancoleman/orderedmap"
)

type OrderedMapClaims struct {
	jwt.Claims
	Raw string
}

func NewOrderedMapClaims(token *jwt.Token) *OrderedMapClaims {
	return &OrderedMapClaims{Claims: token.Claims, Raw: token.Raw}
}

func (m OrderedMapClaims) MarshalJSON() ([]byte, error) {
	parts := strings.Split(m.Raw, ".")
	if len(parts) != 3 {
		return nil, jwt.ErrTokenMalformed
	}

	p := jwt.NewParser()
	claimBytes, err := p.DecodeSegment(parts[1])
	if err != nil {
		return nil, jwt.ErrTokenMalformed
	}

	o := orderedmap.New()
	if err := json.Unmarshal(claimBytes, o); err != nil {
		return nil, err
	}

	if mapClaims, ok := m.Claims.(jwt.MapClaims); ok {
		for k, v := range mapClaims {
			o.Set(k, v)
		}
	}

	return json.Marshal(o)
}
