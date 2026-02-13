package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	keygenActionInit     = "init"
	keygenActionContinue = "continue"

	keygenStatusPending = "PENDING"
	keygenStatusDone    = "DONE"
	keygenStatusError   = "ERROR"
)

type keygenExecution struct {
	handler *protocol.MultiHandler
}

// SchnorrKeyGenServiceImpl drives FROST Taproot keygen round by round.
//
// It is designed for mobile integration where each call to KeyGen consumes
// all newly received messages and emits all messages that should be sent next.
type SchnorrKeyGenServiceImpl struct {
	mu         sync.Mutex
	executions map[string]*keygenExecution
}

type KeyGenRequest struct {
	Action          string   `json:"action"`
	StateID         string   `json:"state_id,omitempty"`
	SelfID          string   `json:"self_id,omitempty"`
	Participants    []string `json:"participants,omitempty"`
	Threshold       int      `json:"threshold,omitempty"`
	SessionIDBase64 string   `json:"session_id_base64,omitempty"`
	InboundMessages []string `json:"inbound_messages,omitempty"`
}

type KeyGenResponse struct {
	Status            string   `json:"status"`
	StateID           string   `json:"state_id,omitempty"`
	SessionIDBase64   string   `json:"session_id_base64,omitempty"`
	OutboundMessages  []string `json:"outbound_messages,omitempty"`
	EncodedKeyShare   string   `json:"encoded_key_share,omitempty"`
	Error             string   `json:"error,omitempty"`
	ProcessedMessages int      `json:"processed_messages,omitempty"`
}

func (s *SchnorrKeyGenServiceImpl) KeyGen(reqStr string) string {
	req := new(KeyGenRequest)
	if err := json.Unmarshal([]byte(reqStr), req); err != nil {
		return mustJSON(KeyGenResponse{
			Status: keygenStatusError,
			Error:  fmt.Sprintf("invalid request JSON: %v", err),
		})
	}

	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case keygenActionInit:
		return s.handleInit(req)
	case keygenActionContinue:
		return s.handleContinue(req)
	default:
		return mustJSON(KeyGenResponse{
			Status: keygenStatusError,
			Error:  "unsupported action, expected init or continue",
		})
	}
}

func (s *SchnorrKeyGenServiceImpl) handleInit(req *KeyGenRequest) string {
	if strings.TrimSpace(req.SelfID) == "" {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "self_id is required for init"})
	}
	if len(req.Participants) == 0 {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "participants is required for init"})
	}

	participants := make([]party.ID, 0, len(req.Participants))
	for _, id := range req.Participants {
		if strings.TrimSpace(id) == "" {
			return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "participants contains empty id"})
		}
		participants = append(participants, party.ID(id))
	}
	selfID := party.ID(req.SelfID)
	if !party.NewIDSlice(participants).Contains(selfID) {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "self_id must be included in participants"})
	}

	sessionID, sessionIDB64, err := parseOrCreateSessionID(req.SessionIDBase64)
	if err != nil {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: err.Error()})
	}

	start := StartKeygenCommon(true, curve.Secp256k1{}, participants, req.Threshold, selfID, nil, nil, nil)
	handler, err := protocol.NewMultiHandler(start, sessionID)
	if err != nil {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: fmt.Sprintf("failed to initialize keygen: %v", err)})
	}

	stateID, err := newStateID()
	if err != nil {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: fmt.Sprintf("failed to create state id: %v", err)})
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

	return mustJSON(KeyGenResponse{
		Status:           keygenStatusPending,
		StateID:          stateID,
		SessionIDBase64:  sessionIDB64,
		OutboundMessages: outbound,
	})
}

func (s *SchnorrKeyGenServiceImpl) handleContinue(req *KeyGenRequest) string {
	stateID := strings.TrimSpace(req.StateID)
	if stateID == "" {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "state_id is required for continue"})
	}

	execution := s.getExecution(stateID)
	if execution == nil {
		return mustJSON(KeyGenResponse{Status: keygenStatusError, Error: "state_id not found"})
	}

	processed := 0
	for _, encoded := range req.InboundMessages {
		msg, err := DecodeProtocolMessageFromString(encoded)
		if err != nil {
			return mustJSON(KeyGenResponse{Status: keygenStatusError, StateID: stateID, Error: fmt.Sprintf("decode inbound message: %v", err)})
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
		cfg, ok := result.(*TaprootConfig)
		if !ok {
			return s.failAndCleanup(stateID, fmt.Errorf("unexpected keygen result type: %T", result))
		}
		encodedShare, err := EncodeTaprootConfigToString(cfg)
		if err != nil {
			return s.failAndCleanup(stateID, err)
		}
		s.deleteExecution(stateID)
		return mustJSON(KeyGenResponse{
			Status:            keygenStatusDone,
			StateID:           stateID,
			OutboundMessages:  outbound,
			EncodedKeyShare:   encodedShare,
			ProcessedMessages: processed,
		})
	}
	if !isNotFinished(resultErr) {
		return s.failAndCleanup(stateID, resultErr)
	}

	return mustJSON(KeyGenResponse{
		Status:            keygenStatusPending,
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
	return mustJSON(KeyGenResponse{
		Status:  keygenStatusError,
		StateID: stateID,
		Error:   err.Error(),
	})
}

func mustJSON(resp KeyGenResponse) string {
	data, err := json.Marshal(resp)
	if err != nil {
		return `{"status":"ERROR","error":"failed to marshal response"}`
	}
	return string(data)
}

func parseOrCreateSessionID(sessionIDB64 string) ([]byte, string, error) {
	if strings.TrimSpace(sessionIDB64) == "" {
		sessionID := make([]byte, 32)
		if _, err := rand.Read(sessionID); err != nil {
			return nil, "", fmt.Errorf("failed to generate session_id: %w", err)
		}
		return sessionID, base64.StdEncoding.EncodeToString(sessionID), nil
	}
	sessionID, err := base64.StdEncoding.DecodeString(sessionIDB64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid session_id_base64: %w", err)
	}
	if len(sessionID) == 0 {
		return nil, "", errors.New("session_id_base64 cannot decode to empty bytes")
	}
	return sessionID, sessionIDB64, nil
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
			encoded, err := EncodeProtocolMessageToString(msg)
			if err != nil {
				return nil, fmt.Errorf("encode outbound message: %w", err)
			}
			outbound = append(outbound, encoded)
		default:
			return outbound, nil
		}
	}
}

// EncodeProtocolMessageToString serializes a protocol message as base64.
func EncodeProtocolMessageToString(msg *protocol.Message) (string, error) {
	if msg == nil {
		return "", errors.New("protocol message is nil")
	}
	data, err := msg.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeProtocolMessageFromString deserializes a base64-encoded protocol message.
func DecodeProtocolMessageFromString(encoded string) (*protocol.Message, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode protocol message base64: %w", err)
	}
	msg := new(protocol.Message)
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("decode protocol message binary: %w", err)
	}
	return msg, nil
}

func isNotFinished(err error) bool {
	return err != nil && err.Error() == "protocol: not finished"
}
