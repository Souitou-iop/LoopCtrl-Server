// Type-checked executable source for RelayRPCClient.pollRequestTimeout. This
// file is not part of the app target; run it with relay/check_swift_timeout.sh.

precondition(
    RelayRPCClient.pollRequestTimeout(serverPollTimeout: 25, responseGrace: 15) == 40
)
precondition(
    RelayRPCClient.pollRequestTimeout(serverPollTimeout: 2, responseGrace: 15) == 17
)
precondition(
    RelayRPCClient.pollRequestTimeout(serverPollTimeout: 0, responseGrace: 0) == 12
)
print("swift timeout check: PASS (server poll wait + response grace, minimum 12s)")

// A network blip or a local LoopCtrl failure must keep the device session:
// the enrollment token is single-use, so re-registering would fail with 401.
precondition(RelayRPCClient.sessionIsLost(after: .unauthorized))
precondition(!RelayRPCClient.sessionIsLost(after: .transport(-1005)))
precondition(!RelayRPCClient.sessionIsLost(after: .transport(-1001)))
precondition(!RelayRPCClient.sessionIsLost(after: .server(status: 502)))
precondition(!RelayRPCClient.sessionIsLost(after: .protocolFailure("x")))
print("swift session check: PASS (only 401/404 ends the relay device session)")
