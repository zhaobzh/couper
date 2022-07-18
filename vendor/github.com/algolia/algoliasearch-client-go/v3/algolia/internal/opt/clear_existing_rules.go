// Code generated by go generate. DO NOT EDIT.

package opt

import (
	"github.com/algolia/algoliasearch-client-go/v3/algolia/opt"
)

// ExtractClearExistingRules returns the first found ClearExistingRulesOption from the
// given variadic arguments or nil otherwise.
func ExtractClearExistingRules(opts ...interface{}) *opt.ClearExistingRulesOption {
	for _, o := range opts {
		if v, ok := o.(*opt.ClearExistingRulesOption); ok {
			return v
		}
	}
	return nil
}
