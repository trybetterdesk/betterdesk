# Quick support app protocol

What the NeoDesk quick support app sends to the console and what it gets
back. The client (neodeskapp/neodesk-client, `src/onboard/support.rs` and
`src/onboard/caller.rs`) and this package keep to this file.

## Routes

All routes are on the console's address (`https://<console host>`), take
and answer JSON, and need no console session or CSRF token. Every route
but the redeem needs `Authorization: Bearer <session token>`; a token of a
session that ended, or none, gets `401 {"success":false,"error":"invalid_session"}`.
The feedback routes are the exception: they take the token for a day
after the end (below, "Feedback after the session").

| Route | Body | What it does |
|---|---|---|
| `POST /api/support/redeem` | `{code}` | Spends the support code; answers the session token, the supporter's name, how to reach the server and whether the app may offer to stay (below, "Keeping the app after the session"). |
| `POST /api/support/session/device` | `{device_id, uuid, hostname, platform, version}` | The device the app runs on. A refused device is `403 {"error":"device_refused","reason":...}` (docs/failure-reasons.md). |
| `POST /api/support/session/consent` | `{allowed, grants?}` | The person's answer in the quick support window. |
| `POST /api/support/session/password` | `{password}` | The one-time password for the supporter, kept in memory. |
| `GET /api/support/session` | none | The session's state; the app polls it every few seconds. |
| `POST /api/support/session/end` | `{}` | The app closed. |
| `POST /api/support/session/caller` | `{session}` | Whether a connection that came without the password is a signed-in helper (below). |
| `GET /api/support/session/feedback` | none | The feedback form, and whether the session has an answer (below). |
| `POST /api/support/session/feedback` | `{answers}` | The person's answers to the feedback form (below). |

The helper's viewer has one route of its own here, with the console
session of a signed-in account: `POST /api/support/devices/{id}/caller`
(below, "What the helper's viewer learns").

## The caller check (A271)

The person at the computer may accept a connection by click instead of
the one-time password only when the server vouches that the connection is
the browser viewer of a signed-in console helper. Every other connection
needs the password. The app never trusts what the connection says about
itself (its ID, its name); it asks the server.

### When the app asks

The app asks once per incoming connection, when all of these hold:

- the person allowed quick support (the session's status is `allowed`),
- the connection came through the relay (the device got signal's
  RequestRelay for it),
- its first login request has no password, and
- the console's address is HTTPS (A273). On a console reached over plain
  HTTP the app does not ask, and quick support takes only the one-time
  password.

`session` is the relay session's UUID: `RequestRelay.uuid` as signal sent
it to the device, which the device used to reach the relay. The caller
does not choose what the device sends here: it is the relay session the
device itself joined.

### What the server checks

The server vouches when all of these hold, else it refuses:

| Check | Refusal `reason` |
|---|---|
| The app's request came over HTTPS, as the console tells it from the connection or a trusted proxy (`TRUST_PROXY`, `X-Forwarded-Proto`) | `not_https` |
| The quick support session is `allowed` and names its device | `session_state` |
| The relay session runs, to the session's device, from the console's browser viewer (`panel-web-remote`), for a console account and a signed-in browser session of it | `session_not_open` |
| Both sides met on the relay at most 60 seconds ago | `too_late` |
| The server has not vouched for this relay session before | `already_used` |
| The account exists, is not disabled, has Connect to devices (`device.connect`) and the device is in its scope | `no_permission` |

Signal issues a relay ticket for the browser viewer only with the panel's
proof of the signed-in account, the relay pairs exactly two sides on one
ticket, and a used UUID is not issued again. So a relay session that
passes these checks is the helper's viewer and nothing else.

### Answers

The server vouches:

```
200
{"success":true,"vouched":true,"device_id":"523456781","session":"<the relay session's UUID>","helper":"Olga Operator","helper_avatar":"data:image/jpeg;base64,/9j/4AAQ..."}
```

`helper` is the helper's first and last name as the console knows them,
else their user name. `helper_avatar` is the helper account's console picture as
`data:image/png;base64,...` (a picture with see-through parts) or
`data:image/jpeg;base64,...`, scaled down to at most 96 by 96 pixels and
at most 48 KB of text, the `data:` prefix included. It is left out when
the account has no picture or it can't be made that small (a WebP picture
among them, which the server does not decode). The audit log gets a `quick_support_caller` entry
about the helper before the answer goes out; when it can't be written the
answer is `500 {"error":"audit_failed"}` and nobody is vouched for.

The server does not vouch:

```
409
{"success":false,"error":"not_vouched","reason":"session_not_open"}
```

A refusal for `no_permission` writes a `quick_support_caller_refused`
entry about the account. A bad body is `400 {"error":"invalid_body"}`.

### What the app does with the answer

The app offers accepting by click only for a `200` whose `vouched` is
`true`, whose `device_id` is its own ID, whose `session` is the relay
session it asked about and whose `helper` is not empty. It shows the
person `helper` as the name and "From the NeoDesk web console" under it.

Anything else means no click: a `409`, a `404` (a server without this
route), a `401`, any other status, a body it can't read, an answer that
names another device or relay session, no answer within 5 seconds, or a
connection that did not come through the relay. The connection then
needs the password as before, and the connection manager window names
the caller unknown and offers only Decline.

A server without this route keeps working with the app: the helper
connects with the password the app handed over. A client without the
check keeps working with this server; the server only answers when asked.

### Trust

The answer comes over the channel the app already hands the one-time
password over: the console's address from the link, with certificate
checks. Over plain HTTP someone on the way could fake it, so neither side
uses it there (A273): the app does not ask, and the server answers
`not_https`.

## What the helper's viewer learns (A273)

The computer does not tell the viewer why it offers no Allow; the console
knows what it told the app. The viewer of a helper whose quick support
session runs on the device asks, after it sent its login without a
password, at 2, 5 and 10 seconds:

```
POST /api/support/devices/{id}/caller
{"session": "<the viewer's relay session UUID>"}

200
{"success": true, "state": "not_allowed_yet", "app_https": true}
```

The account needs Connect to devices and an open quick support session on
the device (`404 {"error": "no_session"}` otherwise). `app_https` is
whether the app's last request came over HTTPS; it is left out when the
console has not heard from the app since it started (the app polls every
few seconds). `state` is what the console told the app about this relay
session:

| `state` | The viewer |
|---|---|
| `vouched` | keeps waiting: the person sees Allow |
| `not_allowed_yet` | fails with `consent_not_allowed`: the person has not clicked Allow in the quick support window yet |
| `not_https` | fails with `consent_needs_https` |
| `refused` | keeps waiting (any other refusal; the person sees Decline) |
| `not_asked` | with `app_https` false: `consent_needs_https`; otherwise asks again, and at the last check fails with `consent_needs_update`: an app that never asks is too old to accept by click |

The texts are in `docs/failure-reasons.md`. The console keeps the states
in memory for 10 minutes.

## Feedback after the session

When a session the person allowed has ended, the app may ask the person
the console's feedback questions. An admin sets the form up in the
console (Settings, Quick support) and reads the answers there. Both
routes take the session token.

### When the token works

| The session | Feedback routes | The other routes |
|---|---|---|
| `allowed` | work | work |
| `ended` after it was `allowed`, at most 24 hours ago | work | `401 invalid_session` |
| `ended` after it was `allowed`, more than 24 hours ago | `401 invalid_session` | `401 invalid_session` |
| never `allowed`: `opened` or `asking`, `declined`, or `ended` before Allow | `409 {"success":false,"error":"wrong_state"}` (for 24 hours after the end, then `401`) | as before |

The routes count against the console's rate limits like the other app
routes. A call to them does not count as the app calling in: an open
session still needs its polls of `GET /api/support/session`.

### The form

```
GET /api/support/session/feedback

200
{"success":true,
 "form":{"questions":[
    {"id":"q1","kind":"rating","label":"How was the help?","required":true},
    {"id":"q2","kind":"text","label":"Anything else?","required":false,"long":true},
    {"id":"q3","kind":"choice","label":"Which part?","required":false,"options":["Mail","Printer"]},
    {"id":"q4","kind":"yesno","label":"Solved?","required":false}]},
 "given":false}

404
{"success":false,"error":"feedback_off"}
```

`404 feedback_off`: feedback is switched off or the form has no
questions. The app asks nothing then.

The questions come in the order the person sees them; there are at most
10. Each has:

| Field | |
|---|---|
| `id` | A short text, stable for the question: it stays through edits and moves, and an id never names another question later. |
| `kind` | `rating` (1 to 5 stars), `text`, `choice` (one of `options`) or `yesno`. |
| `label` | The question as the admin typed it, at most 200 characters. |
| `required` | Whether the person must answer it. |
| `long` | Only on `text`: a field of several lines instead of one. |
| `options` | Only on `choice`: 2 to 8 texts, each at most 200 characters, none twice. |

`given` is true when the session has an answer already; the app shows no
form then. The form is the form at the moment of the request; an admin
may change it between the GET and the POST.

### The answers

```
POST /api/support/session/feedback
{"answers":{"q1":5,"q2":"Thanks","q3":"Printer","q4":true}}

200
{"success":true}

400
{"success":false,"error":"invalid_answers"}

409
{"success":false,"error":"already_given"}
```

`answers` maps question ids to answers: a whole number from 1 to 5 for
`rating`, text of at most 2000 characters for `text`, one of the
`options` exactly for `choice`, `true` or `false` for `yesno`. A question
left out, `null`, a text of only spaces and an empty choice count as not
answered.

The server checks the answers against the form as it is when the POST
arrives. `400 invalid_answers` when an id is no question of the form, a
value is of the wrong type, a rating is outside 1 to 5, a choice is not
one of the options, a text is over 2000 characters, or a required
question is not answered. The app may read the form again and ask anew.
`404 feedback_off` when the form was switched off in between.

A session takes one answer: a second POST is `409 already_given`. The
console keeps each answer with the questions as they were asked, so a
later edit of the form does not change old answers, and with the
session's device ID and computer name, the helper, the person's name and
email from the session, when the session started and ended, and when the
answer came.

## Keeping the app after the session

After a session, the app may offer the person to keep NeoDesk on the
computer: the installed app (the receiver) with its service, which
enrolls the computer on this server. Whether it may is the console's
setting "Offer to install after quick support" (Settings, Quick support;
on unless an admin turned it off). The redeem answer says so:

```
POST /api/support/redeem
{"code":"K7Q2-M9XD"}

200
{"success":true,"session_token":"...","session":{...},"supporter":"Olga Operator",
 "company":"NeoDesk","server":{...},"console":"https://support.example.com",
 "receiver_offer":{"allowed":true,
                   "admission":"3f9c0d...<48 hex digits>",
                   "expires_at":"2026-11-28T14:05:00Z"}}
```

With the setting off, or when the console could not make an admission,
`receiver_offer` is `{"allowed":false,"admission":null,"expires_at":null}`
and the app offers nothing.

`admission` is a one-time secret that admits one computer on this server
without a join request, also in managed and locked enrollment mode, as a
single-use enrollment token without a folder would. It works for 24 hours
(`expires_at`, RFC 3339 in UTC) on the server that answered the redeem
and on no other; its first use spends it, whether it admitted the
computer or not. The server keeps only its SHA-256. In open mode the
server takes the computer anyway; the app may send the admission there
too.

The installed app sends it once, with its first registration:

```
POST /api/devices/register
{"device_id":"523456781","uuid":"...","hostname":"ANA-LAPTOP","platform":"windows",
 "version":"1.4.7","public_key":"...","admission":"3f9c0d..."}

200  {"status":"approved","device_id":"523456781","device_token":"...",...}
403  {"status":"rejected","device_id":"523456781","error":"admission_rejected",
      "message":"The admission of the quick support session is invalid, expired, or already used"}
```

A registration that carries an enrollment token (`token`) is admitted by
the token, and the admission is not looked at. A refused admission is not
queued for approval: the app tells the person the server did not take
the computer and keeps quick support as it was.

### The other fields of the registration

| Field | |
|---|---|
| `token` | An enrollment token (Devices, Add, Device tokens; the MSI's `TOKEN`): a token for one computer or a rollout token for many (below). In open, managed and locked mode a valid one admits the computer; it lands in the token's folder and organization, whose policies then apply. A wrong one is refused in managed and locked mode and changes nothing in open mode. |
| `group` | A folder (device group) by id or by name in any case (the MSI's `GROUP`), at most 128 bytes. It counts only when a valid `token` admits the computer, and a token with a folder of its own puts the computer there instead. An unknown group is ignored. |
| `admission` | The redeem answer's admission, above. |

### Rollout tokens

A rollout token (`kind: "rollout"` in `POST /api/tokens`, "For many
computers" in the console) admits computers until it expires, reaches
its limit (`max_uses`, 1 to 100000) or is revoked. Both the limit and the
expiry (`expires_in`, at most a year) are required. A token for one
computer is unchanged: it binds to the first computer that joins with it.

- Each computer that joins with a rollout token gets its own
  `device_token`, bound to it, as with a token for one computer. The
  rollout token is never bound to a computer and never works as a
  device's credential.
- Taking a place is atomic: of two registrations at once for the last
  place, one gets it. A computer that is already on the server takes no
  place when it registers again.
- Revoking it stops new joins and leaves the computers that joined alone.
- `rustdesk --deploy --token` takes places of it the same way.

In managed and locked mode a rollout token that admits no more computers
is refused in the shape of a refused enrollment token, with its own code:

```
403  {"status":"rejected","device_id":"523456781","error":"rollout_token_used_up",
      "message":"All the computers the rollout token allows have joined",...}
```

| `error` | |
|---|---|
| `rollout_token_expired` | Its expiry has passed. |
| `rollout_token_revoked` | An admin revoked it. |
| `rollout_token_used_up` | As many computers as its limit joined. |

In open mode it changes nothing, as any token that doesn't admit: the
server takes the computer without the token's folder and organization.

## The unattended caller check (A279)

An installed receiver lets a relayed caller in without someone at the
computer clicking Allow only when the server vouches for the caller and
the receiver's own copy of the rule agrees. The rule, its precedence and
the shared test vectors are in `policy/unattended` (the vectors are
`policy/unattended/testdata/rule-vectors.json`, which the client copies
unchanged); the wire contract is UNATTENDED-CONTRACT.md in the lead's
notes.

```
POST /api/nd/unattended/caller
Authorization: Bearer <device token>
X-Device-Id: <device id>
{"session": "<relay uuid>"}
```

The route is on the console and on the API port, like
`GET /api/nd/device-policy`. The device token must be live and bound to
the device the request names (`RequireDeviceToken`,
`RequireTokenDeviceMatch`): no token is `401`, another device's id is
`403 {"error":"Device ID mismatch"}`, and a banned or soft-deleted
device's token is `401 {"error":"Invalid or unbound access token"}`.
`session` is `RequestRelay.uuid` as signal sent it to the device; a bad
body is `400 {"error":"invalid_body"}`.

The server checks, in this order, and the first that fails refuses:

| Check | Refusal `reason` |
|---|---|
| The request came over HTTPS, as the console tells it from the connection or a trusted proxy (`TRUST_PROXY`, `X-Forwarded-Proto`) | `not_https` |
| The relay session runs and goes to the token's device | `session_not_open` |
| Both sides met on the relay at most 60 seconds ago | `too_late` |
| Nobody asked about this relay session before; the claim is shared with the quick support check, so one session is vouched once whichever route asks | `already_used` |
| The relay ticket names an account: the console's browser viewer (`panel-web-remote`) with a console session (`via: console`), or a desktop app signed in with a client session token (`via: desktop`). A guest's bridge and a desktop app that isn't signed in name none | `no_account` |
| The account exists, is not disabled, its role has Connect to devices and it sees the device (device groups and grants) | `no_permission` |
| The rule allows it now, with the device's current organization policy (`connection.mode`, `security.allowed_operators`) and access policy | `ask_always`, `not_enabled`, `outside_schedule`, `operator_not_allowed` |

Signal names the account on the ticket on every path that makes one:
RequestRelay, and the device's own RelayResponse after a punch that falls
back to the relay, which carries the account the punch request named.

Vouched:

```
200
{"success":true,"vouched":true,"device_id":"523456781","session":"<relay uuid>",
 "helper":"Olga Operator","helper_username":"olga",
 "helper_avatar":"data:image/png;base64,...","via":"console"}
```

`helper` is the account's name as the console shows it (first and last
name, else the username), `helper_avatar` its picture, left out when it
has none, as in the quick support answer. Refused:

```
409
{"success":false,"error":"not_vouched","reason":"outside_schedule"}
```

The audit log, each entry about the account (`target_user_id`), with the
account as the actor when it still exists:

| Action | When | Details |
|---|---|---|
| `unattended_session_started` | Before the `200`; when it can't be written the answer is `500 {"error":"audit_failed"}` and nobody is vouched for | `Unattended session to device <id> started; helper=<name> (<username>); via=console\|desktop; relay_session=<uuid>` |
| `unattended_session_ended` | When the relay ends a vouched session | `Unattended session to device <id> ended; helper=...; started=<RFC 3339>; duration_s=<seconds>; relay_session=<uuid>` |
| `unattended_caller_refused` | A refusal once the relay session named an account (`too_late`, `already_used`, `no_permission` and the rule's reasons) | `Unattended session to device <id> refused; helper=...; reason=<reason>; relay_session=<uuid>` |

The end entry needs the relay and the console in one process: a session
the relay of another instance ends, or one that outlives a restart, gets
none.

The receiver lets the caller in without Allow only for a `200` whose
`vouched` is `true`, whose `device_id` is its own ID and whose `session`
is the relay session it asked about, when its own rule with
`helper_username` as the caller allows it too. Anything else, no answer
within 5 seconds included, means the Allow prompt as before.
