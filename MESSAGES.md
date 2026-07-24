# User-Facing Message Reference

Every message the terminal can show, standardized. Errors carry a stable
code rendered as `[E###] message` (red, no glyph); warnings `[!]`, info
`[*]`, success `[✓]`, and `[SECURITY]` events keep their glyph prefixes and
carry no code. The client catalog lives in `client/src/terminal/messages.ts`;
a drift test (`client/tests/messages.test.ts`) fails CI when this table and
the catalog disagree. Codes are append-only: a shipped code is never
renumbered, only retired.

**Where errors appear.** Most errors print inline in the transcript. The
inbound-discard family (**E505, E506, E507, E508, E511, E512**) is the
exception: those describe a message that arrived and could not be read, not a
command you ran, so they collect in the **discarded-notice panel on the right**
of the screen (and the status strip) instead of interrupting the conversation.
`/clr` empties that panel. On narrow/mobile viewports the panel stays collapsed
and the status strip carries the newest notice.

Code families:

| Family | Domain |
|---|---|
| E1xx | Input and command usage |
| E2xx | Authentication, session, identity |
| E3xx | Network and server responses |
| E4xx | Local encrypted store |
| E5xx | Contacts, messaging, decryption |
| E599 | Unclassified catch-all |

## Errors

| Code | Message | Cause | Remedy |
|---|---|---|---|
| E101 | `unknown command: /<word>` | The slash word is not in the command allowlist (typos included; a "did you mean" hint follows when one is close). | `/help` lists every command and alias. |
| E102 | varies: the specific argument problem plus a usage line | A known command was given missing, extra, or malformed arguments; the parser rejects rather than guessing. | Follow the printed usage line. |
| E103 | `invalid UID (26 Crockford Base32 chars, dashes optional)` | The UID typed at the /recover prompt does not canonicalize to 26 Crockford Base32 characters. | Copy the UID exactly as printed at registration; dashes and case do not matter, O/I/L are auto-corrected. |
| E104 | `invalid recovery code (16 Crockford Base32 chars, dashes optional)` | The recovery code does not canonicalize to 16 Crockford Base32 characters. | Retype one of your saved codes; dashes, spaces, and case do not matter. |
| E105 | `unknown suite - use b1, b2, b3, b4, or all (omit for all)` | `/bench` was given a suite name it does not know. | Run `/bench` with `b1`, `b2`, `b3`, `b4`, `all`, or no argument (which runs all). |
| E201 | `not logged in - /login first` | The command needs an authenticated session and there is none (never logged in, or the session dropped). | `/login`, then retry. |
| E202 | `session expired or invalid - /login again` | The server rejected the session token (15-minute idle expiry, revocation, or a recovery elsewhere). | `/login` to get a fresh session. |
| E203 | `unlock failed` | The passphrase did not decrypt the local store. | Retry the passphrase; if it is lost, /recover (destroys local history) is the only way back in. |
| E204 | `no identity on this device - /register first` | The command needs a local identity store and none exists on this device. | `/register` for a new account, or `/recover` to bring an existing UID onto this device. |
| E205 | `recovery failed - unknown UID or invalid recovery code` | The server rejected the redemption. Deliberately uniform: unknown UID, wrong code, and already-spent code are indistinguishable (anti-enumeration). | Check the UID and try another saved code; each code works once and a successful recovery voids the whole old set. |
| E206 | `passphrase must be at least <N> characters` | The chosen passphrase is shorter than the 12-character minimum. It wraps the local store's key through Argon2id, so length is the main defence against offline guessing on a copied database. | Choose a longer passphrase; a memorable multi-word phrase clears 12 easily. |
| E207 | `passphrases do not match` | The confirmation entry differed from the first entry. | Run the command again and type the same passphrase twice. |
| E208 | `rotation failed` | The current passphrase typed at `/rotate passphrase` did not unlock the store, so the DEK was not re-wrapped. | Retry with the correct current passphrase. |
| E209 | `passphrase must include at least one number and one symbol` | The passphrase is long enough but lacks a digit or a symbol. Symbol means anything that is not a letter or digit, so punctuation and spaces both count. | Add a digit and a punctuation mark or space anywhere in the phrase. |
| E210 | `login rejected - the server does not recognise this device's identity key. If you ran /recover on another device, that replaced the account's key: run /recover here with one of the new codes. Otherwise retry, in case the login challenge expired` | `/login` completed the challenge but the server refused the signature. Almost always because the account was recovered on another device, which enrolls a new identity key and orphans the one held here. The server's 401 is uniform, so an unknown UID or an expired challenge look identical. | Run `/recover` on this device with one of the codes reissued by that recovery. If you did not recover anywhere, retry once in case the challenge expired. |
| E301 | `rate limit reached - try again later` | The server returned 429: too many requests from this client for that endpoint's budget. | Wait and retry; limits refill within minutes (registration and recovery within the hour). |
| E302 | `request failed - is the server running?` | A request failed for a reason other than 401/429: server down, network unreachable, or an unexpected status. | Check connectivity and that the server is up, then retry. |
| E303 | `recipient keys unavailable - unknown UID` | `/verify` asked the server for a bundle and got a uniform 404. | Confirm the contact's UID; they may not exist on this server. |
| E304 | `recipient keys unavailable - unknown UID or no prekeys published` | Sending needed a prekey bundle and the server returned a uniform 404 (nonexistent UID, or a registered user who never uploaded prekeys). | Confirm the UID; the recipient may need to log in once so their client publishes prekeys. |
| E401 | `store is locked - /login to unlock` | The operation touched the encrypted store after auto-lock (10 minutes idle) or `/lock`. | `/login` to unlock, then retry. |
| E402 | `store is corrupt: no identity record` | The store unlocked but holds no identity record: an interrupted registration or a damaged database. | `/wipe` the broken store, then `/register` or `/recover`. |
| E403 | `contacts live in the encrypted store - /login first` | `/add` ran while the store was locked. | `/login`, then add the contact. |
| E404 | `store is locked - /login first (settings live encrypted)` | `/settings rotation` ran while the store was locked (the schedule is stored encrypted). | `/login`, then change the setting. |
| E405 | `store is locked - /login first (trust setting lives encrypted)` | `/settings trust` ran while the store was locked (the trust mode is stored encrypted). | `/login`, then change the setting. |
| E501 | `unknown contact: <target> - /add <uid> [alias] first` | The alias or UID does not match any saved contact. Contacts load from the encrypted store on /login. | `/contacts` to see what is saved; `/add <uid> [alias]` to add. |
| E502 | `no known identity key for <alias> yet - /verify first` | `/verified` ran before any key was pinned for that contact. | `/verify <alias>` to fetch and compare the safety number first. |
| E503 | `<alias> has an unacknowledged key change - /ack <alias> first, then /verify again` | The contact's identity key changed and manual trust mode blocks everything until acknowledged. | `/ack <alias>`, then `/verify` + `/verified` against the new key. |
| E504 | `message too large after encryption - not sent` | The encrypted envelope exceeds the 64 KiB server cap. | Send a shorter message. |
| E505 | `someone sent you a message this device cannot read - the shared session for that conversation is gone here (removed contact, /wipe, or /recover). Message them first with /chat <alias> to set up a fresh handshake` | A ratchet message arrived that no stored session could decrypt. Someone you had an established conversation with is still messaging you, but this device lost the matching session (you `/remove`d them, wiped, or recovered). Also covers replays and corrupted ciphertext. The envelope carries no sender identity by design, so **who** it came from cannot be shown. | Send that contact a message yourself: with no session locally, that runs a fresh PQ-KX handshake and re-syncs both sides. |
| E506 | `discarded message with malformed payload` | The envelope decrypted but its inner payload was not valid. | None locally; the sender's client produced an invalid payload. |
| E507 | `discarded malformed message` | The envelope framing itself could not be parsed. | None locally; indicates a broken or hostile sender. |
| E508 | `could not verify sender identity - message discarded` | A first-contact message arrived but the sender's claimed UID could not be bound to its identity key (bundle fetch failed). | Ask the sender to resend once connectivity is back; the check is a spoofing defence, not optional. |
| E509 | `failed to process an incoming message` | An unexpected error interrupted processing of a live-delivered envelope. | The message stays queued server-side; `/login` again to re-drain the inbox. |
| E510 | `the name '<alias>' is already used by another contact - choose a different alias` | `/rename` targeted a name already held by a different contact; aliases are unique locally. | Pick an unused alias, or `/rename` the other contact first. |
| E511 | `someone is trying to start a conversation with you, but used sign-up keys this device no longer has (usually after /recover or /wipe). Ask them to /remove you and message again so their app picks up your current keys` | A handshake arrived encapsulated to a signed prekey or one-time prekey this device no longer holds. Almost always because `/recover` or `/wipe` replaced your published prekeys while the sender still had the old bundle cached. | Nothing on this side can decrypt it. The sender must re-fetch your current bundle: ask them to `/remove` you and message again. `/keys status` confirms your current prekeys are published. |
| E512 | `a damaged or tampered incoming message was discarded` | A handshake envelope was malformed or failed its AEAD check: corruption in transit, or a deliberately tampered envelope. Not a legitimate contact attempt. | None. Isolated occurrences are noise; a steady stream is worth reporting, since the server should not be able to alter envelopes undetected. |
| E599 | `operation failed` | The catch-all for an unclassified internal error. | Retry; if it repeats, capture the browser console and file an issue. |

## Warnings `[!]`

| Message | Meaning |
|---|---|
| `no active conversation - use /chat <alias|uid> first` | Message text was typed with no focused conversation. |
| `locked or not registered - /login or /register` | The command needs an unlocked store; nothing was changed. |
| `another operation is in progress` | Commands run one at a time; wait for the current one. |
| `auto-locked after 10 minutes idle - /login to unlock` | Idle auto-lock fired; keys were zeroized best-effort. |
| `an identity store already exists on this device - /login (or /wipe to destroy it first)` | `/register` refused to overwrite an existing identity. |
| `no signed prekey uploaded yet` | `/keys status` before the first bundle upload finished. |
| `weekly passphrase rotation is due - /rotate passphrase (configure: /settings rotation)` | The weekly local rotation reminder. Declining is fine and unlogged. |
| `reduced forward secrecy: recipient had no one-time prekeys left; heals once the ratchet takes its first key-encapsulation step` | The handshake ran SPK-only (OPK pool empty); the first ratchet round-trip restores full FS. |
| `session has reduced forward secrecy (no one-time prekey)` | Receiver-side view of the same SPK-only condition. |
| `new contact request from <uid> - /add <uid> [alias] to accept` | An unknown sender's first message is held until accepted. |
| `live delivery disconnected - /login to reconnect` | The WebSocket dropped and will not silently retry. |
| `message history, contacts, and sessions did not survive - they lived only in the old encrypted store` | After /recover: those lived only in the old encrypted store. |
| `your contacts still pin the OLD identity key: your next message triggers their identity-key-change warning, and they should re-verify your safety number` | After /recover: peers see the key-change warning by design. |
| `sending to <alias> is blocked by an unacknowledged key change - the peer will get this timer once you /ack and resume` | A `/timer` change is saved locally but cannot reach the peer yet. |
| `that conversation is no longer available - returned to home` | `/return` pointed at a contact that no longer exists. |
| `removed <alias> (<uid>) - message history kept (add 'purge' to delete it too)` | `/remove` without `purge`: the contact and session are gone, the transcript stays on disk. |
| `no contacts to remove` | `/remove all` with an empty contact list. |
| `removal cancelled - nothing was changed` | The `/remove all` confirmation was declined. |
| `<alias> already goes by that name` | `/rename` to the alias the contact already has. |

## Security events `[SECURITY]`

| Message | Meaning |
|---|---|
| `IDENTITY KEY CHANGED for <alias> - ...` (blocked variant) | Manual trust: the pinned key changed; conversation blocked until `/ack`, then `/verify` + `/verified`. |
| `IDENTITY KEY CHANGED for <alias> - ...` (auto-accepted variant) | Trust-on-first-use: the new key was adopted with a loud warning; treat unexpected changes as possible MITM. |
| `prekey bundle signature verification FAILED for <alias> - the server may be tampering.` | A bundle's SPK/OPK signatures did not verify against the contact's identity key. The action is aborted. |
| `received a message with an INVALID identity signature - discarded` | A KX envelope's identity signature failed verification. |
| `message claiming to be <alias> used the new (unconfirmed) key - DISCARDED` | Manual trust: traffic on a changed key is dropped until re-verification. |
| `sender identity does not match its claimed UID - message DISCARDED` | First-contact spoofing defence: the envelope's key is not the key the server serves for that UID. |
| `sending to <alias> is blocked: an unacknowledged identity-key change was detected. ...` | Send refused while a key change awaits `/ack`. |
| `identity key for <alias> changed and is UNACKNOWLEDGED - sending is blocked. ...` | Shown when focusing a blocked conversation. |
| `recovery codes - shown ONCE, never recoverable. write them down now:` | Registration: the one-time display of the recovery code set. |
| `NEW recovery codes - the old set is now void. shown ONCE, never recoverable. write them down now:` | Recovery: the reissued set; every older code is dead. |
| `recovery will REPLACE the identity store on this device - the identity, keys, contacts and message history held here are destroyed and rebuilt from the recovered account. This is a confirmation, not a refusal: answer yes below to go ahead` | `/recover` confirmation gate before touching anything. Answer `yes` to continue; anything else cancels without changing a thing. |
| `/wipe destroys the local store: identity, keys, history. IRREVERSIBLE without recovery codes. repeat /wipe within 30s to confirm.` | First `/wipe` confirmation gate. |

## Server wire errors

The API returns one uniform JSON shape, `{"error": "<code>"}`, with
deliberately coarse codes so responses cannot be used as an oracle. The client
maps them to E3xx/E2xx messages above.

| Wire code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400/413 | Request failed validation (shape, encoding, size). |
| `auth_failed` | 401 | Authentication failed. Never distinguishes unknown user, bad signature, expired nonce, wrong or spent recovery code. |
| `rate_limited` | 429 | Token-bucket limit hit for this IP/UID and endpoint. |
| `request_failed` | 404/405/... | Uniform catch-all, including unknown routes and IDOR-shaped probes. |
| `internal_error` | 500 | Unhandled server error; no details are ever exposed. |

## Delivery ticks

Sent messages get a right-edge mark on their own echoed line instead of a
transcript line: `✓` delivered to the server queue, `✗` failed (the reason
appears as a coded error in the transcript/status strip).
