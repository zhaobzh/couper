// Code generated by go generate. DO NOT EDIT.

package opt

import (
	"github.com/algolia/algoliasearch-client-go/v3/algolia/opt"
)

// ExtractNumericAttributesForFiltering returns the first found NumericAttributesForFilteringOption from the
// given variadic arguments or nil otherwise.
func ExtractNumericAttributesForFiltering(opts ...interface{}) *opt.NumericAttributesForFilteringOption {
	for _, o := range opts {
		if v, ok := o.(*opt.NumericAttributesForFilteringOption); ok {
			return v
		}
	}
	return nil
}
