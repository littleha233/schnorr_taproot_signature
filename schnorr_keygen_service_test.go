package multiparty

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	frostkeygen "github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

func TestSchnorrKeyGenServiceImpl_KeyGenAndSignTaproot(t *testing.T) {
	partyIDs := []party.ID{"phone-a", "phone-b", "phone-c"}
	participants := idsToStrings(partyIDs)
	threshold := 1
	messageHash := []byte("taproot-message-hash")

	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i + 1)
	}
	sessionContext, err := BuildSchnorrKeyGenSessionContext(participants, threshold, base64.StdEncoding.EncodeToString(sessionID))
	require.NoError(t, err)

	services := map[party.ID]*SchnorrKeyGenServiceImpl{
		"phone-a": {},
		"phone-b": {},
		"phone-c": {},
	}

	shares, configs := runUpperTaprootKeygen(t, services, partyIDs, sessionContext)
	require.Len(t, shares, len(partyIDs))
	require.Len(t, configs, len(partyIDs))

	var sharedPublicKey taproot.PublicKey
	for _, id := range partyIDs {
		cfg := configs[id]
		if sharedPublicKey == nil {
			sharedPublicKey = cfg.PublicKey
		}
		require.Equal(t, sharedPublicKey, cfg.PublicKey)
		t.Logf("keygen result party=%s public_key=%s encoded_key_share=%s", id, hex.EncodeToString(cfg.PublicKey), shares[id])
	}

	signers := party.IDSlice{partyIDs[0], partyIDs[1]} // threshold+1 signers
	network := test.NewNetwork(signers)
	handlers := make(map[party.ID]*protocol.MultiHandler, len(signers))

	var wg sync.WaitGroup
	for _, id := range signers {
		h, hErr := protocol.NewMultiHandler(frost.SignTaproot(configs[id], signers, messageHash), nil)
		require.NoError(t, hErr)
		handlers[id] = h
		wg.Add(1)
		go func(id party.ID, handler *protocol.MultiHandler) {
			defer wg.Done()
			test.HandlerLoop(id, handler, network)
		}(id, h)
	}
	wg.Wait()

	var finalSig taproot.Signature
	for _, id := range signers {
		result, rErr := handlers[id].Result()
		require.NoError(t, rErr)
		sig, ok := result.(taproot.Signature)
		require.True(t, ok)
		require.True(t, sharedPublicKey.Verify(sig, messageHash))
		if finalSig == nil {
			finalSig = sig
		} else {
			require.Equal(t, finalSig, sig)
		}
	}
	t.Logf("taproot sign result signature=%s", hex.EncodeToString(finalSig))
}

func TestSchnorrKeyGenServiceImpl_PhaseValidation(t *testing.T) {
	svc := &SchnorrKeyGenServiceImpl{}
	resp := callUpperKeygen(t, svc, SchnorrKeyGenRequest{Phase: 99})
	require.Equal(t, KeyGenStatusError, resp.Status)
	require.Contains(t, resp.Error, "unsupported phase")
}

func TestTaprootKeyShareStorageCodec(t *testing.T) {
	partyIDs := []party.ID{"a", "b", "c"}
	participants := idsToStrings(partyIDs)
	threshold := 1

	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i + 9)
	}
	sessionContext, err := BuildSchnorrKeyGenSessionContext(participants, threshold, base64.StdEncoding.EncodeToString(sessionID))
	require.NoError(t, err)

	services := map[party.ID]*SchnorrKeyGenServiceImpl{
		"a": {},
		"b": {},
		"c": {},
	}
	_, configs := runUpperTaprootKeygen(t, services, partyIDs, sessionContext)

	cfg := configs["a"]
	stored, err := EncodeTaprootKeyShareForStorage(cfg)
	require.NoError(t, err)
	require.Contains(t, stored, keyShareEnvelopePrefix)

	decoded, err := DecodeTaprootKeyShareFromStorage(stored)
	require.NoError(t, err)
	require.Equal(t, cfg.ID, decoded.ID)
	require.Equal(t, cfg.Threshold, decoded.Threshold)
	require.Equal(t, cfg.PublicKey, decoded.PublicKey)
	require.Equal(t, cfg.ChainKey, decoded.ChainKey)
	require.True(t, cfg.PrivateShare.Equal(decoded.PrivateShare))
}

func runUpperTaprootKeygen(t *testing.T, services map[party.ID]*SchnorrKeyGenServiceImpl, partyIDs []party.ID, sessionContext string) (map[party.ID]string, map[party.ID]*frostkeygen.TaprootConfig) {
	t.Helper()
	stateIDs := make(map[party.ID]string, len(partyIDs))
	inbox := make(map[party.ID][]string, len(partyIDs))
	shares := make(map[party.ID]string, len(partyIDs))

	for _, id := range partyIDs {
		req := SchnorrKeyGenRequest{
			Phase:          KeyGenPhaseInit,
			SelfID:         string(id),
			SessionContext: sessionContext,
		}
		resp := callUpperKeygen(t, services[id], req)
		require.Equal(t, KeyGenStatusPending, resp.Status)
		require.NotEmpty(t, resp.StateID)
		stateIDs[id] = resp.StateID
		routeUpperMessages(t, partyIDs, inbox, resp.OutboundMessages)
	}

	const maxTurns = 20
	for turn := 0; turn < maxTurns && len(shares) < len(partyIDs); turn++ {
		progress := false
		for _, id := range partyIDs {
			if _, done := shares[id]; done {
				continue
			}
			req := SchnorrKeyGenRequest{
				Phase:           KeyGenPhaseContinue,
				StateID:         stateIDs[id],
				InboundMessages: inbox[id],
			}
			inbox[id] = nil

			resp := callUpperKeygen(t, services[id], req)
			require.NotEqual(t, KeyGenStatusError, resp.Status, resp.Error)
			routeUpperMessages(t, partyIDs, inbox, resp.OutboundMessages)
			if resp.Status == KeyGenStatusDone {
				require.NotEmpty(t, resp.EncodedKeyShare)
				shares[id] = resp.EncodedKeyShare
			}
			if resp.Status == KeyGenStatusDone || resp.ProcessedMessages > 0 || len(resp.OutboundMessages) > 0 {
				progress = true
			}
		}
		require.True(t, progress, "keygen made no progress")
	}
	require.Len(t, shares, len(partyIDs))

	configs := make(map[party.ID]*frostkeygen.TaprootConfig, len(shares))
	for id, encoded := range shares {
		cfg, err := DecodeTaprootKeyShareFromStorage(encoded)
		require.NoError(t, err)
		configs[id] = cfg
	}
	return shares, configs
}

func idsToStrings(ids []party.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

func callUpperKeygen(t *testing.T, service *SchnorrKeyGenServiceImpl, req SchnorrKeyGenRequest) SchnorrKeyGenResponse {
	t.Helper()
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	respBytes := service.KeyGen(string(reqBytes))
	resp := SchnorrKeyGenResponse{}
	err = json.Unmarshal([]byte(respBytes), &resp)
	require.NoError(t, err)
	return resp
}

func routeUpperMessages(t *testing.T, partyIDs []party.ID, inbox map[party.ID][]string, outbound []string) {
	t.Helper()
	for _, encoded := range outbound {
		msg, err := frostkeygen.DecodeProtocolMessageFromString(encoded)
		require.NoError(t, err)
		for _, id := range partyIDs {
			if msg.IsFor(id) {
				inbox[id] = append(inbox[id], encoded)
			}
		}
	}
}
