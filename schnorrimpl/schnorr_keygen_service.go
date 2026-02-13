package schnorrimpl

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
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

// SchnorrKeyGenSessionContext carries static keygen parameters in one compact token.
type SchnorrKeyGenSessionContext struct {
	SessionIDBase64 string   `json:"session_id_base64"`
	Participants    []string `json:"participants"`
	Threshold       int      `json:"threshold"`
}

type keygenExecution struct {
	handler *protocol.MultiHandler
}

// SchnorrKeyGenServiceImpl is a mobile-facing wrapper over the lower FROST Taproot SDK.
type SchnorrKeyGenServiceImpl struct {
	mu         sync.Mutex
	executions map[string]*keygenExecution
}

// BuildSchnorrKeyGenSessionContext creates a compact context token used in phase=1.
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

	sid, err := normalizeOrGenerateSessionID(sessionIDBase64, true)
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

// DecodeSchnorrKeyGenSessionContext decodes the token produced by BuildSchnorrKeyGenSessionContext.
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
	ctx.SessionIDBase64, err = normalizeOrGenerateSessionID(ctx.SessionIDBase64, false)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

// KeyGen drives FROST Taproot keygen with a single JSON-string entrypoint.
func (s *SchnorrKeyGenServiceImpl) KeyGen(reqStr string) string {
	req := new(SchnorrKeyGenRequest)
	if err := json.Unmarshal([]byte(reqStr), req); err != nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("invalid request JSON: %v", err)})
	}

	switch req.Phase {
	case KeyGenPhaseInit:
		return s.handleInit(req)
	case KeyGenPhaseContinue:
		return s.handleContinue(req)
	default:
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "unsupported phase, expected 1(init) or 2(continue)"})
	}
}

func (s *SchnorrKeyGenServiceImpl) handleInit(req *SchnorrKeyGenRequest) string {
	selfID := strings.TrimSpace(req.SelfID)
	if selfID == "" {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "self_id is required for phase=1"})
	}

	ctx, err := DecodeSchnorrKeyGenSessionContext(req.SessionContext)
	if err != nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: err.Error()})
	}
	if !containsString(ctx.Participants, selfID) {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "self_id must be included in session_context participants"})
	}

	sessionID, err := base64.StdEncoding.DecodeString(ctx.SessionIDBase64)
	if err != nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("invalid session_id_base64: %v", err)})
	}

	participants := toPartyIDs(ctx.Participants)
	start := frost.KeygenTaproot(party.ID(selfID), participants, ctx.Threshold)
	handler, err := protocol.NewMultiHandler(start, sessionID)
	if err != nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("failed to initialize keygen: %v", err)})
	}

	stateID, err := newStateID()
	if err != nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: fmt.Sprintf("failed to create state id: %v", err)})
	}

	s.mu.Lock()
	if s.executions == nil {
		s.executions = make(map[string]*keygenExecution)
	}
	s.executions[stateID] = &keygenExecution{handler: handler}
	s.mu.Unlock()

	outbound, err := drainOutbound(handler)
	if err != nil {
		return s.failAndCleanup(stateID, err)
	}

	return mustJSON(SchnorrKeyGenResponse{
		Status:           KeyGenStatusPending,
		StateID:          stateID,
		OutboundMessages: outbound,
	})
}

func (s *SchnorrKeyGenServiceImpl) handleContinue(req *SchnorrKeyGenRequest) string {
	stateID := strings.TrimSpace(req.StateID)
	if stateID == "" {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "state_id is required for phase=2"})
	}

	execution := s.getExecution(stateID)
	if execution == nil {
		return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, Error: "state_id not found"})
	}

	processed := 0
	for _, encoded := range req.InboundMessages {
		msg, err := decodeProtocolMessageFromString(encoded)
		if err != nil {
			return mustJSON(SchnorrKeyGenResponse{Status: KeyGenStatusError, StateID: stateID, Error: fmt.Sprintf("decode inbound message: %v", err)})
		}
		execution.handler.Accept(msg)
		processed++
	}

	outbound, err := drainOutbound(execution.handler)
	if err != nil {
		return s.failAndCleanup(stateID, err)
	}

	result, resultErr := execution.handler.Result()
	if resultErr == nil {
		cfg, ok := result.(*frost.TaprootConfig)
		if !ok {
			return s.failAndCleanup(stateID, fmt.Errorf("unexpected keygen result type: %T", result))
		}
		encodedShare, err := EncodeTaprootKeyShareForStorage(cfg)
		if err != nil {
			return s.failAndCleanup(stateID, err)
		}
		s.deleteExecution(stateID)
		return mustJSON(SchnorrKeyGenResponse{
			Status:            KeyGenStatusDone,
			StateID:           stateID,
			OutboundMessages:  outbound,
			EncodedKeyShare:   encodedShare,
			ProcessedMessages: processed,
		})
	}
	if !isNotFinished(resultErr) {
		return s.failAndCleanup(stateID, resultErr)
	}

	return mustJSON(SchnorrKeyGenResponse{
		Status:            KeyGenStatusPending,
		StateID:           stateID,
		OutboundMessages:  outbound,
		ProcessedMessages: processed,
	})
}

func (s *SchnorrKeyGenServiceImpl) getExecution(stateID string) *keygenExecution {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.executions[stateID]
}

func (s *SchnorrKeyGenServiceImpl) deleteExecution(stateID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.executions, stateID)
}

func (s *SchnorrKeyGenServiceImpl) failAndCleanup(stateID string, err error) string {
	s.deleteExecution(stateID)
	return mustJSON(SchnorrKeyGenResponse{
		Status:  KeyGenStatusError,
		StateID: stateID,
		Error:   err.Error(),
	})
}

type taprootConfigWire struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte
	PublicKey          []byte
	ChainKey           []byte
	VerificationShares map[party.ID][]byte
}

// EncodeTaprootKeyShareForStorage serializes TaprootConfig into a versioned base64 token.
func EncodeTaprootKeyShareForStorage(config *frost.TaprootConfig) (string, error) {
	if config == nil {
		return "", errors.New("taproot config is nil")
	}
	if config.PrivateShare == nil {
		return "", errors.New("taproot config private share is nil")
	}

	privateShare, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal private share: %w", err)
	}

	verificationShares := make(map[party.ID][]byte, len(config.VerificationShares))
	for id, point := range config.VerificationShares {
		if point == nil {
			return "", fmt.Errorf("verification share for %s is nil", id)
		}
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("marshal verification share for %s: %w", id, err)
		}
		verificationShares[id] = pointBytes
	}

	wire := taprootConfigWire{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateShare,
		PublicKey:          append([]byte(nil), config.PublicKey...),
		ChainKey:           append([]byte(nil), config.ChainKey...),
		VerificationShares: verificationShares,
	}
	raw, err := cbor.Marshal(&wire)
	if err != nil {
		return "", fmt.Errorf("marshal taproot config: %w", err)
	}
	return keyShareEnvelopePrefix + base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeTaprootKeyShareFromStorage restores a key share encoded by EncodeTaprootKeyShareForStorage.
func DecodeTaprootKeyShareFromStorage(stored string) (*frost.TaprootConfig, error) {
	if !strings.HasPrefix(stored, keyShareEnvelopePrefix) {
		return nil, fmt.Errorf("invalid key share prefix, expected %q", keyShareEnvelopePrefix)
	}

	payloadBase64 := strings.TrimPrefix(stored, keyShareEnvelopePrefix)
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("decode key share base64: %w", err)
	}

	wire := new(taprootConfigWire)
	if err = cbor.Unmarshal(payload, wire); err != nil {
		return nil, fmt.Errorf("decode key share payload: %w", err)
	}

	share := curve.Secp256k1{}.NewScalar().(*curve.Secp256k1Scalar)
	if err = share.UnmarshalBinary(wire.PrivateShare); err != nil {
		return nil, fmt.Errorf("unmarshal private share: %w", err)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, len(wire.VerificationShares))
	for id, rawPoint := range wire.VerificationShares {
		point := curve.Secp256k1{}.NewPoint().(*curve.Secp256k1Point)
		if err = point.UnmarshalBinary(rawPoint); err != nil {
			return nil, fmt.Errorf("unmarshal verification share for %s: %w", id, err)
		}
		verificationShares[id] = point
	}

	return &frost.TaprootConfig{
		ID:                 wire.ID,
		Threshold:          wire.Threshold,
		PrivateShare:       share,
		PublicKey:          taproot.PublicKey(append([]byte(nil), wire.PublicKey...)),
		ChainKey:           append([]byte(nil), wire.ChainKey...),
		VerificationShares: verificationShares,
	}, nil
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

func normalizeOrGenerateSessionID(sessionIDBase64 string, allowGenerate bool) (string, error) {
	sessionIDBase64 = strings.TrimSpace(sessionIDBase64)
	if sessionIDBase64 == "" {
		if !allowGenerate {
			return "", errors.New("session_id_base64 is empty in session context")
		}
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

func toPartyIDs(participants []string) []party.ID {
	out := make([]party.ID, 0, len(participants))
	for _, id := range participants {
		out = append(out, party.ID(id))
	}
	return out
}

func containsString(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func newStateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func drainOutbound(handler *protocol.MultiHandler) ([]string, error) {
	outbound := make([]string, 0)
	ch := handler.Listen()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return outbound, nil
			}
			encoded, err := encodeProtocolMessageToString(msg)
			if err != nil {
				return nil, fmt.Errorf("encode outbound message: %w", err)
			}
			outbound = append(outbound, encoded)
		default:
			return outbound, nil
		}
	}
}

func encodeProtocolMessageToString(msg *protocol.Message) (string, error) {
	if msg == nil {
		return "", errors.New("protocol message is nil")
	}
	data, err := msg.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func decodeProtocolMessageFromString(encoded string) (*protocol.Message, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode protocol message base64: %w", err)
	}
	msg := new(protocol.Message)
	if err = msg.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("decode protocol message binary: %w", err)
	}
	return msg, nil
}

func isNotFinished(err error) bool {
	return err != nil && err.Error() == "protocol: not finished"
}

func mustJSON(resp SchnorrKeyGenResponse) string {
	data, err := json.Marshal(resp)
	if err != nil {
		return `{"status":"ERROR","error":"failed to marshal response"}`
	}
	return string(data)
}
