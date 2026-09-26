package extension

// ClientOutputs contains copied, untrusted client extension outputs. A missing
// key means absent; a present value must be constructed with NewRawValue so an
// explicit null remains distinct from absence. Verified results use Results.
type ClientOutputs map[string]RawValue

// ClientOutputsFromRaw copies decoded values at a transport adapter boundary.
func ClientOutputsFromRaw(values map[string]any) (ClientOutputs, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) > MaxEntries {
		return nil, ErrTooManyEntries
	}
	out := make(ClientOutputs, len(values))
	for id, value := range values {
		raw, err := NewRawValue(value)
		if err != nil {
			return nil, err
		}
		out[id] = raw
	}
	return out, nil
}
