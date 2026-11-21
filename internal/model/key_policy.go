package model

import "fmt"

type KeyPolicy struct {
	Revision int64 `json:"revision"`
	Retain   bool  `json:"retain"`
}

func (p KeyPolicy) Validate() error {
	if p.Revision < 1 {
		return fmt.Errorf("invalid key policy revision")
	}
	return nil
}
