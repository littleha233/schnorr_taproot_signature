package keygen

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func TestTaprootConfigCodecRoundTrip(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	rounds := make([]round.Session, 0, len(partyIDs))
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(true, group, partyIDs, 1, partyID, nil, nil, nil)([]byte("taproot-codec-test"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err)
		if done {
			break
		}
	}

	resultRound, ok := rounds[0].(*round.Output)
	require.True(t, ok)
	cfg, ok := resultRound.Result.(*TaprootConfig)
	require.True(t, ok)

	encoded, err := EncodeTaprootConfigToString(cfg)
	require.NoError(t, err)
	decoded, err := DecodeTaprootConfigFromString(encoded)
	require.NoError(t, err)

	require.Equal(t, cfg.ID, decoded.ID)
	require.Equal(t, cfg.Threshold, decoded.Threshold)
	require.Equal(t, cfg.PublicKey, decoded.PublicKey)
	require.Equal(t, cfg.ChainKey, decoded.ChainKey)
	require.True(t, cfg.PrivateShare.Equal(decoded.PrivateShare))
	require.Len(t, decoded.VerificationShares, len(cfg.VerificationShares))
	for id, expected := range cfg.VerificationShares {
		actual, ok := decoded.VerificationShares[id]
		require.True(t, ok)
		require.True(t, expected.Equal(actual))
	}
}

func TestSchnorrKeyGenServiceImpl_KeyGenTaproot(t *testing.T) {
	partyIDs := []party.ID{"phone-a", "phone-b", "phone-c"}
	participants := []string{"phone-a", "phone-b", "phone-c"}
	threshold := 1
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i + 1)
	}
	sessionIDBase64 := base64.StdEncoding.EncodeToString(sessionID)

	services := map[party.ID]*SchnorrKeyGenServiceImpl{
		"phone-a": {},
		"phone-b": {},
		"phone-c": {},
	}
	stateIDs := make(map[party.ID]string, len(partyIDs))
	inbox := make(map[party.ID][]string, len(partyIDs))
	shares := make(map[party.ID]string, len(partyIDs))

	for _, id := range partyIDs {
		req := KeyGenRequest{
			Action:          keygenActionInit,
			SelfID:          string(id),
			Participants:    participants,
			Threshold:       threshold,
			SessionIDBase64: sessionIDBase64,
		}
		resp := callKeygen(t, services[id], req)
		require.Equal(t, keygenStatusPending, resp.Status)
		require.NotEmpty(t, resp.StateID)
		require.Equal(t, sessionIDBase64, resp.SessionIDBase64)
		stateIDs[id] = resp.StateID
		routeMessages(t, partyIDs, inbox, resp.OutboundMessages)
	}

	const maxTurns = 20
	for turn := 0; turn < maxTurns && len(shares) < len(partyIDs); turn++ {
		progress := false
		for _, id := range partyIDs {
			if _, done := shares[id]; done {
				continue
			}
			req := KeyGenRequest{
				Action:          keygenActionContinue,
				StateID:         stateIDs[id],
				InboundMessages: inbox[id],
			}
			inbox[id] = nil

			resp := callKeygen(t, services[id], req)
			require.NotEqual(t, keygenStatusError, resp.Status, resp.Error)
			routeMessages(t, partyIDs, inbox, resp.OutboundMessages)

			if resp.Status == keygenStatusDone {
				require.NotEmpty(t, resp.EncodedKeyShare)
				shares[id] = resp.EncodedKeyShare
			}
			if resp.Status == keygenStatusDone || resp.ProcessedMessages > 0 || len(resp.OutboundMessages) > 0 {
				progress = true
			}
		}
		require.True(t, progress, "keygen made no progress")
	}

	require.Len(t, shares, len(partyIDs))

	var publicKey taproot.PublicKey
	for _, id := range partyIDs {
		cfg, err := DecodeTaprootConfigFromString(shares[id])
		require.NoError(t, err)
		if publicKey == nil {
			publicKey = cfg.PublicKey
		}
		require.Equal(t, publicKey, cfg.PublicKey)
		require.Equal(t, threshold, cfg.Threshold)
		require.Equal(t, id, cfg.ID)
		require.Len(t, cfg.VerificationShares, len(partyIDs))
	}
}

func callKeygen(t *testing.T, service *SchnorrKeyGenServiceImpl, req KeyGenRequest) KeyGenResponse {
	t.Helper()
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	respBytes := service.KeyGen(string(reqBytes))
	resp := KeyGenResponse{}
	err = json.Unmarshal([]byte(respBytes), &resp)
	require.NoError(t, err)
	return resp
}

func routeMessages(t *testing.T, partyIDs []party.ID, inbox map[party.ID][]string, outbound []string) {
	t.Helper()
	for _, encoded := range outbound {
		msg, err := DecodeProtocolMessageFromString(encoded)
		require.NoError(t, err)
		for _, id := range partyIDs {
			if msg.IsFor(id) {
				inbox[id] = append(inbox[id], encoded)
			}
		}
	}
}
