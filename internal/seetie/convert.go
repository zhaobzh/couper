package seetie

import (
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zclconf/go-cty/cty"
)

var validKey = regexp.MustCompile("[a-zA-Z_][a-zA-Z0-9_-]*")

func ValueToMap(val cty.Value) map[string]interface{} {
	result := make(map[string]interface{})
	if val.IsNull() || !val.IsKnown() {
		return result
	}
	var valMap map[string]cty.Value
	if isTuple(val) {
		valMap = val.AsValueSlice()[0].AsValueMap()
	} else {
		valMap = val.AsValueMap()
	}

	for k, v := range valMap {
		if v.IsNull() || !v.IsWhollyKnown() {
			result[k] = nil
			continue
		}
		switch v.Type() {
		case cty.Bool:
			result[k] = v.True()
		case cty.String:
			result[k] = v.AsString()
		case cty.List(cty.String):
			result[k] = ValueToStringSlice(v)
		case cty.Number:
			f, _ := v.AsBigFloat().Float64()
			result[k] = f
		case cty.Map(cty.NilType):
			result[k] = nil
		default:
			if isTuple(v) {
				result[k] = ValueToStringSlice(v)
				continue
			}
			result[k] = nil
		}
	}
	return result
}

func ValueToScopeMap(val cty.Value) (map[string]string, error) {
	scopeMap := make(map[string]string)
	switch val.Type() {
	case cty.NilType:
		return nil, nil
	case cty.String:
		scopeMap["*"] = val.AsString()
		return scopeMap, nil
	default:
		if val.Type().IsObjectType() {
			for k, v := range val.AsValueMap() {
				if v.Type() != cty.String {
					return nil, fmt.Errorf("unsupported value for operation %q in beta_scope", k)
				}
				scopeMap[strings.ToUpper(k)] = v.AsString()
			}
			return scopeMap, nil
		}
	}
	return nil, fmt.Errorf("unsupported value for beta_scope")
}

func ValuesMapToValue(m url.Values) cty.Value {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return MapToValue(result)
}

func ListToValue(l []interface{}) cty.Value {
	var list []cty.Value
	for _, v := range l {
		list = append(list, GoToValue(v))
	}
	return cty.TupleVal(list)
}

func GoToValue(v interface{}) cty.Value {
	switch v := v.(type) {
	case string:
		return cty.StringVal(ToString(v))
	case bool:
		return cty.BoolVal(v)
	case int64:
		return cty.NumberIntVal(v)
	case float64:
		return cty.NumberFloatVal(v)
	case []string:
		var list []interface{}
		for _, s := range v {
			list = append(list, s)
		}
		return ListToValue(list)
	case []interface{}:
		return ListToValue(v)
	case map[string]interface{}:
		return MapToValue(v)
	default:
		return cty.NullVal(cty.String)
	}
}

func MapToValue(m map[string]interface{}) cty.Value {
	if m == nil {
		return cty.MapValEmpty(cty.NilType)
	}

	ctyMap := make(map[string]cty.Value)

	for k, v := range m {
		if !validKey.MatchString(k) {
			continue
		}
		switch v := v.(type) {
		case []string:
			var list []interface{}
			for _, s := range v {
				list = append(list, s)
			}
			ctyMap[k] = ListToValue(list)
		case []interface{}:
			ctyMap[k] = ListToValue(v)
		case map[string]interface{}:
			ctyMap[k] = MapToValue(v)
		default:
			ctyMap[k] = GoToValue(v)
		}
	}

	if len(ctyMap) == 0 {
		return cty.MapValEmpty(cty.NilType) // prevent attribute access on nil values
	}

	return cty.ObjectVal(ctyMap)
}

func HeaderToMapValue(headers http.Header) cty.Value {
	ctyMap := make(map[string]cty.Value)
	for k, v := range headers {
		if validKey.MatchString(k) {
			if len(v) == 0 {
				ctyMap[strings.ToLower(k)] = cty.StringVal("")
				continue
			}
			ctyMap[strings.ToLower(k)] = cty.StringVal(v[0]) // TODO: ListVal??
		}
	}
	if len(ctyMap) == 0 {
		return cty.MapValEmpty(cty.String)
	}
	return cty.MapVal(ctyMap)
}

func CookiesToMapValue(cookies []*http.Cookie) cty.Value {
	ctyMap := make(map[string]cty.Value)
	for _, cookie := range cookies {
		ctyMap[cookie.Name] = cty.StringVal(cookie.Value) // TODO: ListVal??
	}

	if len(ctyMap) == 0 {
		return cty.MapValEmpty(cty.String)
	}
	return cty.MapVal(ctyMap)
}

func ValueToStringSlice(src cty.Value) []string {
	var l []string
	if !src.IsKnown() || src.IsNull() {
		return l
	}

	switch src.Type() {
	case cty.NilType:
		return l
	case cty.Bool, cty.Number, cty.String:
		return append(l, ValueToString(src))
	default:
		for _, s := range src.AsValueSlice() {
			if !s.IsKnown() {
				continue
			}
			l = append(l, ValueToString(s))
		}
	}
	return l
}

var whitespaceRegex = regexp.MustCompile(`^\s*$`)

// ValueToString explicitly drops all other (unknown) types and
// converts non whitespace strings or numbers to its string representation.
func ValueToString(v cty.Value) string {
	if v.IsNull() || !v.IsKnown() {
		return ""
	}

	switch v.Type() {
	case cty.String:
		str := v.AsString()
		if whitespaceRegex.MatchString(str) {
			return ""
		}
		return str
	case cty.Number:
		n := v.AsBigFloat()
		ni, accuracy := n.Int(nil)
		if accuracy == big.Exact {
			return ni.String()
		}
		return n.String()
	default:
		return ""
	}
}

func ValueToInt(v cty.Value) (n int64) {
	if !v.IsWhollyKnown() {
		return n
	}

	switch v.Type() {
	case cty.String:
		i, err := strconv.Atoi(v.AsString())
		if err == nil {
			n = int64(i)
		}
	case cty.Number:
		bn := v.AsBigFloat()
		n, _ = bn.Int64()
	}

	return n
}

func ValueToLogFields(val cty.Value) logrus.Fields {
	if val.IsNull() || !val.IsKnown() {
		return nil
	}

	fields := logrus.Fields{}

	for k, v := range val.AsValueMap() {
		if isTuple(v) {
			fields[k] = ValueToLogFieldsFromTuple(v)
		} else {
			switch v.Type() {
			case cty.Bool:
				fields[k] = v.True()
			case cty.String:
				fields[k] = v.AsString()
			case cty.Number:
				f, _ := v.AsBigFloat().Float64()
				fields[k] = f
			default:
				if isObject(v) {
					fields[k] = ValueToLogFields(v)
				}
			}
		}
	}

	return fields
}

func ValueToLogFieldsFromTuple(val cty.Value) []interface{} {
	if !isTuple(val) {
		return nil
	}

	var values []interface{}
	for _, v := range val.AsValueSlice() {
		if isTuple(v) {
			values = append(values, ValueToLogFieldsFromTuple(v))
		} else {
			switch v.Type() {
			case cty.Bool:
				values = append(values, v.True())
			case cty.String:
				values = append(values, v.AsString())
			case cty.Number:
				f, _ := v.AsBigFloat().Float64()
				values = append(values, f)
			default:
				if isObject(v) {
					values = append(values, ValueToLogFields(v))
				}
			}
		}
	}

	return values
}

func SliceToString(sl []interface{}) string {
	var str []string
	for _, s := range sl {
		if result := ToString(s); result != "" {
			str = append(str, result)
		}
	}
	return strings.Join(str, ",")
}

func ToString(s interface{}) string {
	switch s := s.(type) {
	case []string:
		return strings.Join(s, ",")
	case []interface{}:
		return SliceToString(s)
	case string:
		return s
	case int:
		return strconv.Itoa(s)
	case float64:
		return fmt.Sprintf("%0.f", s)
	case bool:
		if !s {
			return "false"
		}
		return "true"
	default:
		return ""
	}
}

// isObject checks by type name since object is not comparable by type.
func isObject(v cty.Value) bool {
	if v.IsNull() {
		return false
	}
	return v.Type().FriendlyNameForConstraint() == "object"
}

// isTuple checks by type name since tuple is not comparable by type.
func isTuple(v cty.Value) bool {
	if v.IsNull() {
		return false
	}
	return v.Type().FriendlyNameForConstraint() == "tuple"
}
