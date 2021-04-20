package errors

import (
	"net/http"
	"reflect"
	"strings"
	"unicode"
)

var (
	AccessControl  = &Error{synopsis: "access control error", httpStatus: http.StatusForbidden}
	Backend        = &Error{synopsis: "backend error", httpStatus: http.StatusBadGateway}
	ClientRequest  = &Error{synopsis: "client request error", httpStatus: http.StatusBadRequest}
	Evaluation     = &Error{synopsis: "expression evaluation error"}
	Configuration  = &Error{synopsis: "configuration error", httpStatus: http.StatusInternalServerError}
	Proxy          = &Error{synopsis: "proxy error", httpStatus: http.StatusBadGateway}
	Request        = &Error{synopsis: "request error", httpStatus: http.StatusBadGateway}
	RouteNotFound  = &Error{synopsis: "route not found error", httpStatus: http.StatusNotFound}
	Server         = &Error{synopsis: "internal server error", httpStatus: http.StatusInternalServerError}
	ServerShutdown = &Error{synopsis: "server shutdown error", httpStatus: http.StatusInternalServerError}
	Timeout        = &Error{synopsis: "timeout server error", httpStatus: http.StatusGatewayTimeout}
)

func TypeToSnake(t interface{}) string {
	typeStr := reflect.TypeOf(t).String()
	if strings.Contains(typeStr, ".") { // package name removal
		typeStr = strings.Split(typeStr, ".")[1]
	}
	var result []rune
	for i, r := range typeStr {
		if i > 0 && unicode.IsUpper(r) {
			result = append(result, '_')
		}
		result = append(result, unicode.ToLower(r))
	}

	return string(result)
}