# aspnetTicketTool
Do some edits with ASPNET tickets, but don't know how.

Mainly used to craft ASPNET sessions when you got the machine keys info.

Here is the vibe documentation, enjoy:

## Usage

- Decrypt
```bat
.\aspnetTicketTool decrypt <validationKey> <decryptionKey> <encryptedTicket>
```

- Encrypt (clone an existing ticket, optionally change username and expiration minutes)
```bat
.\aspnetTicketTool encrypt <validationKey> <decryptionKey> <existingEncryptedTicket> <newUsernameOrDashToKeep> <newUserDataOrDashToKeep> <minutes>
```

Notes:
- Algorithms are fixed to `validation=HMACSHA256` and `decryption=AES` in this tool.
- `newUsernameOrDashToKeep`: pass `-` to keep the original username.
- `newUserDataOrDashToKeep`: pass `-` to keep the original username.
- On success, `encrypt` prints two lines: the human-readable ticket info, then the new encrypted ticket.

## Examples

- Decrypt
```bat
.\aspnetTicketTool decrypt EBF9... B26C... <encTicket>
```
Sample output:
```
=====================
Version: 1
Name: john
IssueDate: 2025-10-20T16:10:00.0000000Z
Expiration: 2025-10-20T18:10:00.0000000Z
IsPersistent: False
UserData:
CookiePath: /
=====================
```

- Encrypt (change username and set 120-minute expiry)
```bat
.\aspnetTicketTool encrypt EBF9... B26C... <existingEncTicket> john admin 120
```

- Encrypt (keep existing username, set 60-minute expiry)
```bat
.\aspnetTicketTool encrypt EBF9... B26C... <existingEncTicket> - - 60
```

## How it works (brief)

- Writes a temporary `.config` with your `machineKey`
- Creates a child `AppDomain` that loads `System.Web` with that config
- Uses `FormsAuthentication.Decrypt`/`Encrypt`
- Cleans up the temporary config file afterward

## Troubleshooting

- "Failed to decrypt ticket": Ensure your app actually used `HMACSHA256` + `AES` and that keys are the exact hex strings from `web.config` without separators.
- "Invalid minutes": Provide an integer (e.g., `60`).
- Still failing? The ticket may come from a different `machineKey`/algorithm pair, or be corrupted/truncated.

## Security

- Keep your `validationKey`/`decryptionKey` secret.
- Avoid pasting keys/tickets in logs or screenshares.
- Prefer running on a trusted machine and delete any artifacts after use.
