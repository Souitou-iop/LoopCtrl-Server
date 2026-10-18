// Type-checked executable source for RelayRPCClient.pollRequestTimeout. This
// file is not part of the app target; run it with relay/check_swift_timeout.sh.

import Foundation

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

// A relay may sit behind a reverse-proxy path prefix.
func url(_ s: String) -> URL { URL(string: s)! }
precondition(RelayRPCClient.endpoint(base: url("https://hs.example/loopctrl-relay/"), path: "/v1/device/poll")?
    .absoluteString == "https://hs.example/loopctrl-relay/v1/device/poll")
precondition(RelayRPCClient.endpoint(base: url("https://hs.example/loopctrl-relay"), path: "/v1/device/poll")?
    .absoluteString == "https://hs.example/loopctrl-relay/v1/device/poll")
precondition(RelayRPCClient.endpoint(base: url("https://relay.example"), path: "/v1/device/poll")?
    .absoluteString == "https://relay.example/v1/device/poll")
let token = String(repeating: "a", count: 32)
precondition((try? RelayEnrollment(baseURL: url("https://hs.example/loopctrl-relay/"), token: token)) != nil)
precondition((try? RelayEnrollment(baseURL: url("https://relay.example"), token: token)) != nil)
precondition((try? RelayEnrollment(baseURL: url("http://hs.example/loopctrl-relay/"), token: token)) == nil)
precondition((try? RelayEnrollment(baseURL: url("https://hs.example/x?y=1"), token: token)) == nil)
precondition((try? RelayEnrollment(baseURL: url("https://hs.example/a/../b"), token: token)) == nil)
precondition((try? RelayEnrollment(baseURL: url("https://u:p@hs.example/"), token: token)) == nil)
print("swift relay URL check: PASS (path prefix allowed; http, query, dot segments, credentials rejected)")
