package protocol

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/wire"
)

// readVectorCountWithMinimum rejects impossible vector counts before callers
// reserve memory for decoded elements. The generic wire check can only assume
// that each element occupies one byte; protocol records often have a much
// larger minimum encoding.
func readVectorCountWithMinimum(r *wire.Reader, label string, minimumItemBytes int) uint64 {
	count := r.ReadVectorCount(label)
	if r.Err() != nil {
		return 0
	}
	if minimumItemBytes <= 0 {
		r.SetErr(fmt.Errorf("protocol: %s minimum encoded size is invalid", label))
		return 0
	}
	if count > uint64(r.Remaining()/minimumItemBytes) {
		r.SetErr(fmt.Errorf("protocol: %s count %d cannot fit in %d remaining bytes", label, count, r.Remaining()))
		return 0
	}
	return count
}
