package keygen

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type taprootConfigMarshalled struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte
	PublicKey          []byte
	ChainKey           []byte
	VerificationShares map[party.ID][]byte
}

// MarshalBinary serializes TaprootConfig into a stable binary representation.
func (r *TaprootConfig) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("taproot config is nil")
	}
	if r.PrivateShare == nil {
		return nil, errors.New("taproot config private share is nil")
	}

	privateShare, err := r.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal private share: %w", err)
	}

	verificationShares := make(map[party.ID][]byte, len(r.VerificationShares))
	for id, point := range r.VerificationShares {
		if point == nil {
			return nil, fmt.Errorf("verification share for %s is nil", id)
		}
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal verification share for %s: %w", id, err)
		}
		verificationShares[id] = pointBytes
	}

	wire := taprootConfigMarshalled{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       privateShare,
		PublicKey:          append([]byte(nil), r.PublicKey...),
		ChainKey:           append([]byte(nil), r.ChainKey...),
		VerificationShares: verificationShares,
	}
	return cbor.Marshal(&wire)
}

// UnmarshalBinary deserializes TaprootConfig from MarshalBinary output.
func (r *TaprootConfig) UnmarshalBinary(data []byte) error {
	if r == nil {
		return errors.New("taproot config is nil")
	}
	wire := new(taprootConfigMarshalled)
	if err := cbor.Unmarshal(data, wire); err != nil {
		return fmt.Errorf("unmarshal taproot config: %w", err)
	}

	share := curve.Secp256k1{}.NewScalar().(*curve.Secp256k1Scalar)
	if err := share.UnmarshalBinary(wire.PrivateShare); err != nil {
		return fmt.Errorf("unmarshal private share: %w", err)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, len(wire.VerificationShares))
	for id, raw := range wire.VerificationShares {
		point := curve.Secp256k1{}.NewPoint().(*curve.Secp256k1Point)
		if err := point.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("unmarshal verification share for %s: %w", id, err)
		}
		verificationShares[id] = point
	}

	*r = TaprootConfig{
		ID:                 wire.ID,
		Threshold:          wire.Threshold,
		PrivateShare:       share,
		PublicKey:          append([]byte(nil), wire.PublicKey...),
		ChainKey:           append([]byte(nil), wire.ChainKey...),
		VerificationShares: verificationShares,
	}
	return nil
}

// EncodeTaprootConfigToString encodes TaprootConfig into a base64 string for storage.
func EncodeTaprootConfigToString(config *TaprootConfig) (string, error) {
	data, err := config.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeTaprootConfigFromString decodes a TaprootConfig produced by EncodeTaprootConfigToString.
func DecodeTaprootConfigFromString(encoded string) (*TaprootConfig, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode taproot config base64: %w", err)
	}
	config := new(TaprootConfig)
	if err := config.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return config, nil
}
