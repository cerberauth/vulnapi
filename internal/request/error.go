package request

import "errors"

func NilResponseError() error {
	return errors.New("response is nil")
}
