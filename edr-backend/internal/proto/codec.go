// internal/proto/codec.go
// JSON codec for gRPC so we can use plain Go structs without protoc.
// The agent must use the same codec (registered on both sides).
//
// Register with: encoding.RegisterCodec(proto.JSONCodec{})

package proto

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/encoding"
)

func init() {
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec is a gRPC codec that uses JSON encoding.
type JSONCodec struct{}

func (JSONCodec) Marshal(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json codec marshal: %w", err)
	}
	return b, nil
}

func (JSONCodec) Unmarshal(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("json codec unmarshal: %w", err)
	}
	return nil
}

func (JSONCodec) Name() string {
	return "json"
}
