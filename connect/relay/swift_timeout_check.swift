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
