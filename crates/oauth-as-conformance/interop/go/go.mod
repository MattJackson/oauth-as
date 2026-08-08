// A SECOND independent judge of the AS, in a different language and from a different author than
// the pinned Rust `oauth2 = "=5.0.0"` client the rest of this harness drives.
//
// golang.org/x/oauth2 is maintained by the Go project, has no relationship to this repository or
// to ramosbugs/oauth2-rs, and parses and type-checks every response itself. Where the two clients
// agree, two independent implementations of RFC 6749 / RFC 8628 accepted the same wire bytes.
//
// PINNED EXACTLY, and go.sum locks the module hashes, for the same reason the Rust client is
// pinned exactly: a silent upgrade must never be able to change what "conformant" means here.
//
// The `go` directive is 1.25.0 because that is what golang.org/x/oauth2 v0.36.0's own go.mod
// declares; it is its floor, not a preference of ours.
module oauth-as-interop

go 1.25.0

require golang.org/x/oauth2 v0.36.0
