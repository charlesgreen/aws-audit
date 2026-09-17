package redact

import (
	"bytes"
	"encoding/json"
)

const redacted = "[REDACTED]"

var secretKeys = map[string]bool{
	"PreSharedKey":                 true,
	"UserData":                     true,
	"HeaderValue":                  true,
	"CustomerGatewayConfiguration": true,
}

// JSON walks a JSON document and replaces secret-bearing fields.
func JSON(in []byte) ([]byte, error) {
	trim := bytes.TrimSpace(in)
	if len(trim) == 0 {
		return in, nil
	}
	var v any
	if err := json.Unmarshal(trim, &v); err != nil {
		return in, nil
	}
	walk(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}

func walk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if secretKeys[k] {
				if s, ok := child.(string); ok && s != "" {
					t[k] = redacted
					continue
				}
			}
			walk(child)
		}
	case []any:
		for _, child := range t {
			walk(child)
		}
	}
}
