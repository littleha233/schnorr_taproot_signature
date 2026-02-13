package multiparty

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	frostkeygen "github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

const (
	// KeyGenPhaseInit starts a new keygen session.
	KeyGenPhaseInit = 1
	// KeyGenPhaseContinue advances an existing keygen session with inbound messages.
	KeyGenPhaseContinue = 2
)

const (
	// KeyGenStatusPending means more rounds are required.
	KeyGenStatusPending = "PENDING"
	// KeyGenStatusDone means keygen is complete and key share is returned.
	KeyGenStatusDone = "DONE"
	// KeyGenStatusError means the request failed and the state is aborted.
	KeyGenStatusError = "ERROR"
)

const (
	keyGenSessionContextPrefix = "mpsig.taproot.keygen.ctx.v1."
	keyShareEnvelopePrefix     = "mpsig.taproot.keyshare.v1."
)

// SchnorrKeyGenRequest is the upper-layer request used by mobile clients.
//
// Each party repeatedly calls the same KeyGen entrypoint:
// 1) phase=1 (init) once
// 2) phase=2 (continue) multiple times with inbound_messages
// until status becomes DONE.
type SchnorrKeyGenRequest struct {
	Phase           int      `json:"phase"`
	StateID         string   `json:"state_id,omitempty"`
	SelfID          string   `json:"self_id,omitempty"`
	SessionContext  string   `json:"session_context,omitempty"`
	InboundMessages []string `json:"inbound_messages,omitempty"`
}

// SchnorrKeyGenResponse is the upper-layer response for mobile clients.
type SchnorrKeyGenResponse struct {
	Status            string   `json:"status"`
	StateID           string   `json:"state_id,omitempty"`
	OutboundMessages  []string `json:"outbound_messages,omitempty"`
	EncodedKeyShare   string   `json:"encoded_key_share,omitempty"`
	ProcessedMessages int      `json:"processed_messages,omitempty"`
	Error             string   `json:"error,omitempty"`
}

// SchnorrKeyGenSessionContext is the compact session input used during INIT.
// It carries all static keygen parameters so they don't need to be repeated in each request.
type SchnorrKeyGenSessionContext struct {
	SessionIDBase64 string   `json:"session_id_base64"`
	Participants    []string `json:"participants"`
	Threshold       int      `json:"threshold"`
}

// SchnorrKeyGenServiceImpl is a mobile-facing wrapper over the lower FROST Taproot keygen SDK.
type SchnorrKeyGenServiceImpl struct {
	sdk frostkeygen.SchnorrKeyGenServiceImpl
}

// BuildSchnorrKeyGenSessionContext encodes static keygen parameters into a compact token.
//
// If sessionIDBase64 is empty, a random 32-byte session ID is generated.
func BuildSchnorrKeyGenSessionContext(participants []string, threshold int, sessionIDBase64 string) (string, error) {
	normalizedParticipants, err := normalizeParticipants(participants)
	if err != nil {
		return "", err
	}
	if threshold < 0 || threshold >= len(normalizedParticipants) {
		return "", fmt.Errorf("invalid threshold %d for %d participants", threshold, len(normalizedParticipants))
	}

	sid, err := normalizeOrGenerateSessionID(sessionIDBase64)
	if err != nil {
		return "", err
	}

	ctx := SchnorrKeyGenSessionContext{
		SessionIDBase64: sid,
		Participants:    normalizedParticipants,
		Threshold:       threshold,
	}
	data, err := json.Marshal(&ctx)
	if err != nil {
		return "", fmt.Errorf("marshal session context: %w", err)
	}
	return keyGenSessionContextPrefix + base64.StdEncoding.EncodeToString(data), nil
}

// DecodeSchnorrKeyGenSessionContext decodes the context token produced by BuildSchnorrKeyGenSessionContext.
func DecodeSchnorrKeyGenSessionContext(encoded string) (*SchnorrKeyGenSessionContext, error) {
	if !strings.HasPrefix(encoded, keyGenSessionContextPrefix) {
		return nil, fmt.Errorf("invalid session context prefix, expected %q", keyGenSessionContextPrefix)
	}

	payloadBase64 := strings.TrimPrefix(encoded, keyGenSessionContextPrefix)
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("decode session context base64: %w", err)
	}

	ctx := new(SchnorrKeyGenSessionContext)
	if err = json.Unmarshal(payload, ctx); err != nil {
		return nil, fmt.Errorf("decode session context JSON: %w", err)
	}

	ctx.Participants, err = normalizeParticipants(ctx.Participants)
	if err != nil {
		return nil, err
	}
	if ctx.Threshold < 0 || ctx.Threshold >= len(ctx.Participants) {
		return nil, fmt.Errorf("invalid threshold %d for %d participants", ctx.Threshold, len(ctx.Participants))
	}
	ctx.SessionIDBase64, err = normalizeOrGenerateSessionID(ctx.SessionIDBase64)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

// KeyGen drives FROST Taproot keygen for mobile clients with a single JSON-string entrypoint.
//
// reqStr is a JSON-serialized SchnorrKeyGenRequest.
// return value is a JSON-serialized SchnorrKeyGenResponse.
func (s *SchnorrKeyGenServiceImpl) KeyGen(reqStr string) string {
	upperReq := new(SchnorrKeyGenRequest)
	if err := json.Unmarshal([]byte(reqStr), upperReq); err != nil {
		return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("invalid request JSON: %v", err)})
	}

	var lowerReq frostkeygen.KeyGenRequest
	switch upperReq.Phase {
	case KeyGenPhaseInit:
		if strings.TrimSpace(upperReq.SelfID) == "" {
			return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "self_id is required for phase=1"})
		}
		ctx, err := DecodeSchnorrKeyGenSessionContext(upperReq.SessionContext)
		if err != nil {
			return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: err.Error()})
		}
		lowerReq = frostkeygen.KeyGenRequest{
			Action:          "init",
			SelfID:          upperReq.SelfID,
			Participants:    ctx.Participants,
			Threshold:       ctx.Threshold,
			SessionIDBase64: ctx.SessionIDBase64,
		}
	case KeyGenPhaseContinue:
		if strings.TrimSpace(upperReq.StateID) == "" {
			return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "state_id is required for phase=2"})
		}
		lowerReq = frostkeygen.KeyGenRequest{
			Action:          "continue",
			StateID:         upperReq.StateID,
			InboundMessages: upperReq.InboundMessages,
		}
	default:
		return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "unsupported phase, expected 1(init) or 2(continue)"})
	}

	lowerReqBytes, err := json.Marshal(lowerReq)
	if err != nil {
		return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("marshal lower request: %v", err)})
	}

	lowerRespStr := s.sdk.KeyGen(string(lowerReqBytes))
	lowerResp := new(frostkeygen.KeyGenResponse)
	if err = json.Unmarshal([]byte(lowerRespStr), lowerResp); err != nil {
		return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("invalid lower response: %v", err)})
	}

	upperResp := SchnorrKeyGenResponse{
		Status:            normalizeStatus(lowerResp.Status),
		StateID:           lowerResp.StateID,
		OutboundMessages:  lowerResp.OutboundMessages,
		ProcessedMessages: lowerResp.ProcessedMessages,
		Error:             lowerResp.Error,
	}

	if strings.TrimSpace(lowerResp.EncodedKeyShare) != "" {
		stored, wrapErr := encodeStoredKeyShare(lowerResp.EncodedKeyShare)
		if wrapErr != nil {
			return mustUpperJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, StateID: lowerResp.StateID, Error: wrapErr.Error()})
		}
		upperResp.EncodedKeyShare = stored
	}

	if upperResp.Status == "" {
		upperResp.Status = KeyGenStatusError
		if upperResp.Error == "" {
			upperResp.Error = "empty status from lower response"
		}
	}

	return mustUpperJSON(upperResp)
}

// EncodeTaprootKeyShareForStorage serializes a key share with an explicit versioned envelope.
func EncodeTaprootKeyShareForStorage(config *frostkeygen.TaprootConfig) (string, error) {
	sdkEncoded, err := frostkeygen.EncodeTaprootConfigToString(config)
	if err != nil {
		return "", err
	}
	return encodeStoredKeyShare(sdkEncoded)
}

// DecodeTaprootKeyShareFromStorage restores a key share previously saved by EncodeTaprootKeyShareForStorage.
func DecodeTaprootKeyShareFromStorage(stored string) (*frostkeygen.TaprootConfig, error) {
	sdkEncoded, err := decodeStoredKeyShare(stored)
	if err != nil {
		return nil, err
	}
	return frostkeygen.DecodeTaprootConfigFromString(sdkEncoded)
}

func normalizeParticipants(participants []string) ([]string, error) {
	if len(participants) == 0 {
		return nil, errors.New("participants must not be empty")
	}

	out := make([]string, 0, len(participants))
	seen := make(map[string]struct{}, len(participants))
	for _, p := range participants {
		id := strings.TrimSpace(p)
		if id == "" {
			return nil, errors.New("participants contains empty id")
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate participant id: %s", id)
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeOrGenerateSessionID(sessionIDBase64 string) (string, error) {
	sessionIDBase64 = strings.TrimSpace(sessionIDBase64)
	if sessionIDBase64 == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generate session id: %w", err)
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}

	raw, err := base64.StdEncoding.DecodeString(sessionIDBase64)
	if err != nil {
		return "", fmt.Errorf("invalid session_id_base64: %w", err)
	}
	if len(raw) == 0 {
		return "", errors.New("session_id_base64 cannot decode to empty bytes")
	}
	return sessionIDBase64, nil
}

func encodeStoredKeyShare(sdkEncoded string) (string, error) {
	if strings.TrimSpace(sdkEncoded) == "" {
		return "", errors.New("empty sdk key share")
	}
	return keyShareEnvelopePrefix + sdkEncoded, nil
}

func decodeStoredKeyShare(stored string) (string, error) {
	if !strings.HasPrefix(stored, keyShareEnvelopePrefix) {
		return "", fmt.Errorf("invalid key share prefix, expected %q", keyShareEnvelopePrefix)
	}
	sdkEncoded := strings.TrimPrefix(stored, keyShareEnvelopePrefix)
	if strings.TrimSpace(sdkEncoded) == "" {
		return "", errors.New("empty key share payload")
	}
	return sdkEncoded, nil
}

func normalizeStatus(status string) string {
	s := strings.ToUpper(strings.TrimSpace(status))
	switch s {
	case KeyGenStatusPending, KeyGenStatusDone, KeyGenStatusError:
		return s
	default:
		return s
	}
}

func mustUpperJSON(resp SchnorrKeyGenResponse) string {
	data, err := json.Marshal(resp)
	if err != nil {
		return `{"status":"ERROR","error":"failed to marshal response"}`
	}
	return string(data)
}
