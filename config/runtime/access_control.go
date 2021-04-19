package runtime

import (
	"strings"

	"github.com/avenga/couper/accesscontrol"
	"github.com/avenga/couper/config"
	"github.com/avenga/couper/errors"
)

type ACDefinitions map[string]*AccessControl

type AccessControl struct {
	Control      accesscontrol.AccessControl
	ErrorHandler []*config.ErrorHandler
}

func (m ACDefinitions) Add(name string, ac accesscontrol.AccessControl, eh []*config.ErrorHandler) error {
	n := strings.TrimSpace(name)
	if _, ok := m[n]; ok {
		return errors.Configuration.Message("accessControl already defined: " + n)
	}

	m[n] = &AccessControl{
		Control:      ac,
		ErrorHandler: eh,
	}
	return nil
}

func (m ACDefinitions) MustExist(name string) {
	if m == nil {
		panic("no accessControl configuration")
	}

	if _, ok := m[name]; !ok {
		panic("accessControl is not defined: " + name)
	}
}
