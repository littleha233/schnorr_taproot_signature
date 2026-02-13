# Schnorr KeyGen iOS Integration Guide

## 1. Overview

This guide describes how to integrate `schnorrimpl.SchnorrKeyGenServiceImpl` in iOS when this Go project is compiled into an XCFramework.

Design split:
- `protocols/frost` = low-level crypto SDK (round engine + FROST Taproot protocol).
- `schnorrimpl` = application-facing orchestration layer (`KeyGen(reqStr) -> respStr`).

## 2. Per-Phone Service Lifecycle

Each phone (party) should create **one service instance** and keep it alive for the whole keygen session.

Recommended lifecycle per iOS app process:
- Create once when entering keygen flow:
  - `service := &schnorrimpl.SchnorrKeyGenServiceImpl{}`
- Reuse same `service` object for all keygen rounds.
- Do not recreate `service` between rounds unless you also persist and restore internal state (not implemented yet).

Why:
- In-memory map `executions[stateID]` holds active protocol handlers.
- `state_id` in response points to that in-memory handler.
- If service is recreated, `state_id` becomes unknown and `phase=2` will fail with `state_id not found`.

## 3. How to Start a Session

### 3.1 Build session context (once)
One side (or your backend coordinator) constructs shared context:
- participants list
- threshold
- session_id_base64 (recommended deterministic shared value)

Call:
- `BuildSchnorrKeyGenSessionContext(participants, threshold, sessionIDBase64)`

This returns `session_context` token string.

### 3.2 Each phone sends phase=1
Request JSON:
```json
{
  "phase": 1,
  "self_id": "phone-a",
  "session_context": "..."
}
```

Response:
- `status=PENDING`
- `state_id`
- `outbound_messages[]`

Save `state_id` locally for this session.

## 4. Round Loop (phase=2)

Each phone repeats:
1. Collect newly received network messages for this session into `inbound_messages[]`.
2. Call:
```json
{
  "phase": 2,
  "state_id": "...",
  "inbound_messages": ["..."]
}
```
3. Handle response:
- `status=PENDING`: continue loop, send `outbound_messages`.
- `status=DONE`: keygen completed, read `encoded_key_share` and persist securely.
- `status=ERROR`: abort this session and surface error.

## 5. How to Route outbound_messages

Each outbound item is an encoded `protocol.Message`.
Routing policy should be based on decoded headers:
- `To == ""`: send to all participants except self (logical broadcast).
- `To == "party-id"`: send only to that recipient (p2p).

In tests this is done by checking `msg.IsFor(id)` after decode.

### Broadcast reliability
For production network, if your threat model includes equivocation by relay/bad peers:
- Keep broadcast fanout server-side deterministic (same payload to all).
- Track message IDs/hash and deduplicate.
- Preserve message bytes exactly; do not re-encode protobuf/json fields.

## 6. How to Handle inbound_messages

For each device:
- Keep per-session inbound queue keyed by `state_id` (or by protocol session id/SSID if you decode it).
- Pass only newly received messages to `phase=2`.
- Duplicates are safe (handler drops duplicates), but avoid unnecessary retries for performance.

## 7. Key Share Persistence

On `DONE`, store `encoded_key_share` from response.

Use:
- `DecodeTaprootKeyShareFromStorage(encoded)` to restore config when signing later.

Security recommendations:
- Store in iOS Keychain / Secure Enclave protected blob.
- Bind to wallet/account id + participant id.
- Encrypt at rest with app-level key wrapping.

## 8. Practical Orchestration Model

Recommended actor model per phone:
- `KeyGenCoordinator`
  - owns one `SchnorrKeyGenServiceImpl`
  - owns one `state_id`
  - has inbound queue from transport layer
  - triggers `phase=2` when queue non-empty or on short timer

Pseudo-flow:
1. init -> get `state_id` + outbound -> send
2. on inbound arrival -> continue -> outbound -> send
3. repeat until done -> persist key share

## 9. Common Pitfalls

- Recreating service instance between rounds -> `state_id not found`.
- Different `session_context` across phones -> protocol never converges.
- Sending messages to wrong session -> ignored by `CanAccept`.
- Treating all outbound as full broadcast -> works functionally but wastes bandwidth.

## 10. Current Validation

`TestSchnorrKeyGenServiceImpl_KeyGenAndSignTaproot` verifies full flow:
- 3-party keygen (phones)
- logs generated public key + encoded key shares
- uses generated shares for Taproot threshold signing
- verifies signature against shared public key
