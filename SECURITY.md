# Security

owt-stack carries the security-sensitive parts of the apps built on it: cross-origin
protection, sealed sessions, password hashing, sign-in throttling, OAuth and JWT
verification, the response headers and content security policy. A weakness here is a
weakness in every app.

**Report a vulnerability privately** through GitHub's private vulnerability reporting
on this repository (Security → Report a vulnerability), not in a public issue or pull
request. Include the crate, the version or commit, and how to reproduce it; a failing
test is the best report. Expect an acknowledgement within a week.

A fix ships as a `fix:` release (see the README's "Working on owt-stack"), and the
GitHub security advisory names the affected versions. The crates are not on crates.io,
so there is no RustSec advisory; an app learns of the fix from the release and its
lockfile's pin.

Supported: the latest release only. A problem in an older tag is fixed by upgrading.
