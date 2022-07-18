// Code generated by go generate. DO NOT EDIT.

package opt

import (
	"github.com/algolia/algoliasearch-client-go/v3/algolia/opt"
)

// ExtractPrimary returns the first found PrimaryOption from the
// given variadic arguments or nil otherwise.
func ExtractPrimary(opts ...interface{}) *opt.PrimaryOption {
	for _, o := range opts {
		if v, ok := o.(*opt.PrimaryOption); ok {
			return v
		}
	}
	return nil
}
