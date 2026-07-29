# User-Facing Message Reference

Every message the terminal can show, standardized. Errors carry a stable
code rendered as `[E###] message` (red, no glyph); warnings `[!]`, info
`[*]`, success `[✓]`, and `[SECURITY]` events keep their glyph prefixes and
carry no code. The client catalog lives in `client/src/terminal/messages.ts`;
a drift test (`client/tests/messages.test.ts`) fails CI when this table and
the catalog disagree. Codes are append-only: a shipped code is never
renumbered, only retired.

**House style.** Plain sentences, and say what to do. State the problem, then
the action, as two sentences rather than joining them with a dash: "Server might
be temporarily down. Please contact the host or try again." reads as help, where
"request failed, is the server running?" reads as a log line. No dash is used as
a connector anywhere in this document or the catalog it mirrors.

**Colour.** Each level has a colour, but the colour is never the only signal:
the marker is also literal text (`[!]`, `[SECURITY]`, the E-code), and the
message text itself is always printed in the scheme's foreground rather than the
level's colour. That is what makes `/settings color event <slot> <#rrggbb>` safe
to expose. It retints the markers in both the transcript and the footer status
strip; the `[SECURITY]` strip treatment is fixed white-on-red and is not
configurable.

**Where errors appear.** Most errors print inline in the transcript. The
inbound-discard family (**E505, E506, E507, E508, E511, E512, E513**) is the
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
| E5xx | Contacts, messaging, groups, decryption |
| E599 | Unclassified catch-all |

## Errors

| Code | Message | Cause | Remedy |
|---|---|---|---|
| E101 | `unknown command: /<word>` | The slash word is not in the command allowlist. Typos included; a "did you mean" hint follows when one is close. | `/help` lists every command and alias. |
| E102 | varies: the specific argument problem plus a usage line | A known command was given missing, extra, or malformed arguments. The parser rejects rather than guessing. | Follow the printed usage line. |
| E103 | `That UID is not valid. It should be 26 characters; dashes and capitalisation do not matter.` | The UID typed at the /recover prompt does not canonicalize to 26 Crockford Base32 characters. | Copy the UID exactly as printed at registration. O, I and L are auto-corrected. |
| E104 | `That recovery code is not valid. It should be 16 characters; dashes, spaces and capitalisation do not matter.` | The recovery code does not canonicalize to 16 Crockford Base32 characters. | Retype one of your saved codes. |
| E105 | `Unknown benchmark suite. Choose b1, b2, b3, b4, or all, or leave it out to run everything.` | `/bench` was given a suite name it does not know. | Run `/bench` with `b1`, `b2`, `b3`, `b4`, `all`, or no argument, which runs all. |
| E106 | `There is no color scheme called '<name>'. Run /settings scheme list to see the ones you can switch to.` | `/settings scheme` or `/settings scheme delete` named a scheme that is neither a preset nor one of yours. | `/settings scheme list` shows them all. `/settings scheme new <name>` creates one. |
| E107 | `'<name>' cannot be used as a scheme name. Use 1 to 24 characters starting with a letter, and avoid the preset names and the words new, delete, list and reset.` | A custom scheme name was malformed, reserved, or a preset name. Also what `/settings scheme delete dark` gets: the three presets are immutable and cannot be deleted, which is what makes them a reliable way back. | Pick a name matching the rule. To change how a preset looks, switch to it and use `/settings color`, which forks it. |
| E108 | `You already have the maximum of <n> custom schemes. Run /settings scheme delete <name> to free a slot.` | You already have the maximum number of custom schemes. | Delete one you no longer use. |
| E109 | `A scheme called '<name>' already exists. Choose another name, or switch to it and use /settings color to change it.` | `/settings scheme new` was given a name already in use. | Choose a different name, or switch to the existing scheme and edit it. |
| E201 | `You are not logged in. Please run /login first.` | The command needs an authenticated session and there is none, because you never logged in or the session dropped. | `/login`, then retry. |
| E202 | `Your session has expired. Please run /login again.` | The server rejected the session token, after the 15-minute idle expiry, a revocation, or a recovery elsewhere. | `/login` to get a fresh session. |
| E203 | `Unlock failed. Please check your passphrase and try again.` | The passphrase did not decrypt the local store. Also what an armed duress passphrase prints, deliberately, so the two are indistinguishable. | Retry the passphrase. If it is lost, `/recover` is the only way back in, and it destroys local history. |
| E204 | `There is no identity on this device. Run /register to create one, or /recover to bring an existing account here.` | The command needs a local identity store and none exists on this device. | `/register` for a new account, or `/recover` to bring an existing UID onto this device. |
| E205 | `Recovery failed. The UID or the code was not accepted, so check both and try another saved code.` | The server rejected the redemption. Deliberately uniform: unknown UID, wrong code, and already-spent code are indistinguishable, which is what stops the endpoint being an enumeration oracle. | Check the UID and try another saved code. Each code works once, and a successful recovery voids the whole old set. |
| E206 | `That passphrase is too short. Please use at least <N> characters.` | The chosen passphrase is shorter than the 12-character minimum. It wraps the local store's key through Argon2id, so length is the main defence against offline guessing on a copied database. | Choose a longer passphrase. A memorable multi-word phrase clears 12 easily. |
| E207 | `The two passphrases did not match. Please run the command again.` | The confirmation entry differed from the first entry. | Run the command again and type the same passphrase twice. |
| E208 | `Rotation failed. The current passphrase was not correct.` | The current passphrase typed at `/rotate passphrase` did not unlock the store, so the DEK was not re-wrapped. | Retry with the correct current passphrase. |
| E209 | `That passphrase needs at least one number and one symbol.` | The passphrase is long enough but lacks a digit or a symbol. Symbol means anything that is not a letter or digit, so punctuation and spaces both count. | Add a digit and a punctuation mark or space anywhere in the phrase. |
| E210 | `The server does not recognise this device's identity key. This usually means /recover was run on another device, which replaces the account key. Run /recover here with one of the new codes, or try again in case the login challenge simply expired.` | `/login` completed the challenge but the server refused the signature. Almost always because the account was recovered on another device, which enrolls a new identity key and orphans the one held here. The server's 401 is uniform, so an unknown UID or an expired challenge look identical. | Run `/recover` on this device with one of the codes reissued by that recovery. If you did not recover anywhere, retry once in case the challenge expired. |
| E211 | `That is already this device's unlock passphrase. Your duress passphrase must be a different one, otherwise every login would silently destroy the account.` | Guards both directions of the same mistake: `/duress set` was given the passphrase that already unlocks the store, or `/rotate passphrase` tried to move the unlock passphrase onto the armed duress one. Either would turn every ordinary login into an unannounced wipe. | Choose a distinct duress passphrase, or a different new unlock passphrase. Run `/duress off` first if you would rather retire the duress one. |
| E301 | `Rate limit reached. Please wait a few minutes and try again.` | The server returned 429, meaning too many requests from this client for that endpoint's budget. | Wait and retry. Limits refill within minutes, and registration and recovery within the hour. |
| E302 | `Server might be temporarily down. Please contact the host or try again.` | A request failed for a reason other than 401 or 429: server down, network unreachable, or an unexpected status. | Check connectivity and that the server is up, then retry. |
| E303 | `Those keys are unavailable. That UID may not exist on this server.` | `/verify` asked the server for a bundle and got a uniform 404. | Confirm the contact's UID. They may not exist on this server. |
| E304 | `The recipient's keys are unavailable. That UID may not exist, or they may not have published any prekeys yet.` | Sending needed a prekey bundle and the server returned a uniform 404, for a nonexistent UID or a registered user who never uploaded prekeys. | Confirm the UID. The recipient may need to log in once so their client publishes prekeys. |
| E401 | `The store is locked. Please run /login to unlock it.` | The operation touched the encrypted store after the 10-minute idle auto-lock or an explicit `/lock`. | `/login` to unlock, then retry. |
| E402 | `The store is damaged and holds no identity record. Run /wipe, then /register or /recover.` | The store unlocked but holds no identity record, after an interrupted registration or a damaged database. | `/wipe` the broken store, then `/register` or `/recover`. |
| E403 | `Contacts are kept in the encrypted store. Please run /login first.` | `/add`, `/remove`, `/rename` or `/favourite` ran while the store was locked. | `/login`, then run the command again. |
| E404 | `Settings are kept in the encrypted store. Please run /login first.` | `/settings rotation` ran while the store was locked, and the schedule is stored encrypted. | `/login`, then change the setting. |
| E405 | `The trust setting is kept in the encrypted store. Please run /login first.` | `/settings trust` ran while the store was locked, and the trust mode is stored encrypted. | `/login`, then change the setting. |
| E406 | `The duress passphrase is sealed with the store. Please run /login first.` | `/duress set`, `/duress off`, or `/duress status` ran while the store was locked. Arming seals a credential from the unlocked store, and the armed flag itself lives encrypted, which is why the raw database cannot answer the question. | `/login`, then run the command again. |
| E501 | `There is no contact called '<target>'. Run /contacts to see the ones you have saved, or /add <uid> [alias] to add this one.` | The alias or UID does not match any saved contact. Contacts load from the encrypted store on `/login`. | `/contacts` to see what is saved, `/add <uid> [alias]` to add. |
| E502 | `No identity key is known for <alias> yet. Please run /verify <alias> first.` | `/verified` ran before any key was pinned for that contact. | `/verify <alias>` to fetch and compare the safety number first. |
| E503 | `<alias> has an unacknowledged key change. Run /ack <alias>, then verify them again.` | The contact's identity key changed and manual trust mode blocks everything until acknowledged. | `/ack <alias>`, then `/verify` and `/verified` against the new key. |
| E504 | `That message is too large to send. Please shorten it and try again.` | The encrypted envelope exceeds the 64 KiB server cap. | Send a shorter message. |
| E505 | `Someone sent you a message this device cannot read, because the shared session for that conversation is gone from here. That happens after removing a contact, /wipe, or /recover. Message them first with /chat <alias> to set up a fresh handshake.` | A ratchet message arrived that no stored session could decrypt. Someone you had an established conversation with is still messaging you, but this device lost the matching session. Also covers replays and corrupted ciphertext. The envelope carries no sender identity by design, so **who** it came from cannot be shown. | Send that contact a message yourself. With no session locally, that runs a fresh PQ-KX handshake and re-syncs both sides. |
| E506 | `A message was discarded because its contents were not valid.` | The envelope decrypted but its inner payload was not valid. | None locally. The sender's client produced an invalid payload. |
| E507 | `A malformed message was discarded.` | The envelope framing itself could not be parsed. | None locally. It indicates a broken or hostile sender. |
| E508 | `The sender's identity could not be verified, so their message was discarded.` | A first-contact message arrived but the sender's claimed UID could not be bound to its identity key, because the bundle fetch failed. | Ask the sender to resend once connectivity is back. The check is a spoofing defence, not optional. |
| E509 | `An incoming message could not be processed. It is still waiting on the server, so run /login again to fetch it.` | An unexpected error interrupted processing of a live-delivered envelope. | The message stays queued server-side. `/login` again to re-drain the inbox. |
| E510 | `The name '<alias>' already belongs to another contact. Please choose a different one.` | `/rename` targeted a name already held by a different contact, and aliases are unique locally. | Pick an unused alias, or `/rename` the other contact first. |
| E511 | `Someone is trying to start a conversation using sign-up keys this device no longer has, which usually follows a /recover or /wipe. Ask them to /remove you and message again so their app picks up your current keys.` | A handshake arrived encapsulated to a signed prekey or one-time prekey this device no longer holds. Almost always because `/recover` or `/wipe` replaced your published prekeys while the sender still had the old bundle cached. | Nothing on this side can decrypt it. The sender must re-fetch your current bundle, so ask them to `/remove` you and message again. `/keys status` confirms your current prekeys are published. |
| E512 | `A damaged or tampered message was discarded.` | A handshake envelope was malformed or failed its AEAD check, from corruption in transit or a deliberately tampered envelope. Not a legitimate contact attempt. | None. Isolated occurrences are noise, but a steady stream is worth reporting, since the server should not be able to alter envelopes undetected. |
| E513 | `A group message was discarded because it did not add up: it came from someone who is not a contact, or its member list did not include both you and the sender.` | A group-bearing payload arrived that failed one of the three admission rules in `messaging.ts::applyIncomingGroup`: the sender is not a contact, the sender is not in the roster they sent, or you are not in it. Each of those is either a bug or a forgery, and neither is worth creating group state for. | None. If someone should be able to reach you, `/add` them first; the contact-request gate governs groups exactly as it governs one-to-one messages. |
| E514 | `There is no group called '<name>' on this device. Run /group list to see the ones you have.` | A `/group` subcommand named a group this device does not hold. | `/group list` shows what exists. If you were invited and it is missing, ask the inviter to invite you again. |
| E515 | `'<name>' cannot be used as a group name. Use 1 to 32 characters: letters, digits, spaces, underscores or hyphens.` | The name would not survive an aligned listing, or could carry an escape sequence. | Rename with the allowed characters. |
| E516 | `You already have a group called '<name>'. Choose another name so the two can be told apart.` | Group names are the handle every `/group` subcommand takes, so two groups sharing one would be unaddressable. | Pick a different name. |
| E517 | `A group needs at least one other member. Name the contacts to include.` | `/group new` was given no members, or only yourself. | Name the contacts to add. |
| E518 | `A group can hold at most <n> members. Every message is sent separately to each one, so the limit keeps a single message from becoming a flood.` | The roster hit the fan-out cap. Each member costs one send against the per-UID rate limit, so an unbounded roster is a way to turn one keystroke into a burst. | Remove someone, or split the group. |
| E519 | `<target> is not a member of '<group>'.` | `/group remove` named someone the roster does not contain. | `/group info <name>` shows the roster. |
| E599 | `Something went wrong. Please try again.` | The catch-all for an unclassified internal error. | Retry. If it repeats, capture the browser console and file an issue. |

## Warnings `[!]`

| Message | Meaning |
|---|---|
| `No active conversation. Use /chat <alias|uid> first.` | Message text was typed with no focused conversation. |
| `Locked or not registered. Please run /login or /register.` | The command needs an unlocked store. Nothing was changed. |
| `Another operation is in progress. Please wait for it to finish.` | Commands run one at a time. |
| `Auto-locked after 10 minutes idle. Run /login to unlock.` | Idle auto-lock fired. Keys were zeroized best-effort. |
| `An identity store already exists on this device. Run /login, or /wipe to destroy it first.` | `/register` refused to overwrite an existing identity. |
| `No signed prekey has been uploaded yet.` | `/keys status` before the first bundle upload finished. |
| `Weekly passphrase rotation is due. Run /rotate passphrase, or configure the reminder with /settings rotation.` | The weekly local rotation reminder. Declining is fine and unlogged. |
| `reduced forward secrecy: recipient had no one-time prekeys left; heals once the ratchet takes its first key-encapsulation step` | The handshake ran with the signed prekey only, because the one-time pool was empty. The first ratchet round-trip restores full forward secrecy. |
| `This session has reduced forward secrecy, because no one-time prekey was used.` | Receiver-side view of the same condition. |
| `New contact request from <uid>. Run /add <uid> [alias] to accept.` | An unknown sender's first message is held until accepted. |
| `Live delivery disconnected. Run /login to reconnect.` | The WebSocket dropped and will not silently retry. |
| `Message history, contacts, and sessions did not survive. They lived only in the old encrypted store.` | Shown after `/recover`. |
| `Your contacts still pin your OLD identity key. Your next message triggers their identity-key-change warning, and they should re-verify your safety number.` | Shown after `/recover`. Peers see the key-change warning by design. |
| `Sending to <alias> is blocked by an unacknowledged key change. They will get this timer once you /ack and resume.` | A `/timer` change is saved locally but cannot reach the peer yet. |
| `That conversation is no longer available, so you are back at home.` | `/return` pointed at a contact that no longer exists. |
| `Removed <alias> (<uid>). Message history was kept; add 'purge' to delete it too.` | `/remove` without `purge`. The contact and session are gone, the transcript stays on disk. |
| `There are no contacts to remove.` | `/remove all` with an empty contact list. |
| `Removal cancelled. Nothing was changed.` | The `/remove all` confirmation was declined. |
| `<alias> already goes by that name.` | `/rename` to the alias the contact already has. |
| `<alias> is already a favourite.` / `<alias> is not a favourite.` | `/favourite` asked for the state the contact is already in. |
| `'<scheme>' is a preset and carries no custom colors, so there is nothing to reset.` | `/settings color reset` on a preset. Presets are never modified, so there is nothing to undo. |
| `Duress passphrase not armed. Nothing was changed.` | The `/duress set` confirmation was declined or cancelled. |
| `Duress passphrase not armed. Run /duress set to arm one, after reading its warning.` | `/duress status` with the feature off. |

## Security events `[SECURITY]`

| Message | Meaning |
|---|---|
| `IDENTITY KEY CHANGED for <alias>. This conversation is now blocked and marked UNVERIFIED. ...` | Manual trust. The pinned key changed, so the conversation is blocked until `/ack`, then `/verify` and `/verified`. |
| `IDENTITY KEY CHANGED for <alias>. The new key was auto-accepted under trust-on-first-use ...` | Trust-on-first-use. The new key was adopted with a loud warning. Treat an unexpected change as a possible machine-in-the-middle. |
| `Prekey bundle signature verification FAILED for <alias>. The server may be tampering.` | A bundle's signed-prekey or one-time-prekey signatures did not verify against the contact's identity key. The action is aborted. |
| `A message arrived with an INVALID identity signature, so it was discarded.` | A handshake envelope's identity signature failed verification. |
| `A message claiming to be <alias> used the new, unconfirmed key, so it was DISCARDED.` | Manual trust. Traffic on a changed key is dropped until re-verification. |
| `The sender's identity does not match its claimed UID, so the message was DISCARDED.` | First-contact spoofing defence. The envelope's key is not the key the server serves for that UID. |
| `sending to <alias> is blocked: an unacknowledged identity-key change was detected. ...` | Send refused while a key change awaits `/ack`. |
| `The identity key for <alias> changed and is UNACKNOWLEDGED, so sending is blocked. ...` | Shown when focusing a blocked conversation. |
| `Recovery codes, shown ONCE and never recoverable. Write them down now:` | Registration. The one-time display of the recovery code set. |
| `NEW recovery codes. The old set is now void. ...` | Recovery. The reissued set; every older code is dead. |
| `Recovery will REPLACE the identity store on this device. ...` | `/recover` confirmation gate before touching anything. Answer `yes` to continue; anything else cancels without changing a thing. |
| `/wipe destroys the local store: identity, keys, history. IRREVERSIBLE without recovery codes. repeat /wipe within 30s to confirm.` | First `/wipe` confirmation gate. |
| `a duress passphrase gives NO warning and NO confirmation. ...` | The `/duress set` warning, shown before anything is armed. The one and only place the feature announces itself, since the trigger never does. |
| `Duress passphrase armed. Typing it at the /login prompt destroys this device and the account ...` | `/duress set` completed. |
| `Duress passphrase ARMED. Typing it at /login destroys this device and the account ...` | `/duress status` with the feature armed. Readable only with the real passphrase; the raw database gives nothing away. |

**What a duress login shows.** Nothing of its own. It renders exactly the
`[E203]` line above, the same one a typo produces, and does not clear the
screen, because anything else would be the tell the feature exists to avoid.
The next `/login` reports `[E204]`, which is then simply true.

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
