# smtpd

Small, embeddable SMTP server library for Go, with an API style similar to the standard HTTP server.

This repository is maintained at [github.com/sibexico/smtpd](https://github.com/sibexico/smtpd). The canonical module path is:

```go
import "github.com/sibexico/smtpd"
```

## Features

- SMTP server with simple message callback:
  - `func(remoteAddr net.Addr, from string, to []string, data []byte) error`
- Optional message-id callback:
  - `func(remoteAddr net.Addr, from string, to []string, data []byte) (string, error)`
- RFC-aligned command handling with enhanced status codes and `Received` header generation.
- TLS support for STARTTLS and implicit TLS listeners.
- STARTTLS-required mode helper for submission-style setups.
- Authentication support for CRAM-MD5, LOGIN, and PLAIN.
- Recipient policy hooks (`RCPT`) and mailbox verification hook (`VRFY`).
- DSN-related ESMTP parameters:
  - `MAIL FROM` supports `SIZE`, `RET`, `ENVID`
  - `RCPT TO` supports `NOTIFY`, `ORCPT`
- Configurable limits and behavior:
  - `MaxSize`, `MaxRecipients`, `Timeout`, `DisableReverseDNS`, `XClientAllowed`
- Graceful shutdown support via `Server.Shutdown(ctx)`.

## Quick Start

```go
package main

import (
    "log"
    "net"

    "github.com/sibexico/smtpd"
)

func mailHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
    log.Printf("mail from=%s to=%v bytes=%d remote=%s", from, to, len(data), remoteAddr.String())
    return nil
}

func main() {
    err := smtpd.ListenAndServe("127.0.0.1:2525", mailHandler, "MyServer", "")
    if err != nil {
        log.Fatal(err)
    }
}
```

## TLS Modes

STARTTLS available (optional for clients):

```go
err := smtpd.ListenAndServeTLS(
    "127.0.0.1:2525",
    "/path/to/server.crt",
    "/path/to/server.key",
    mailHandler,
    "MyServer",
    "mail.example.com",
)
```

STARTTLS required before mail commands (typical submission behavior):

```go
err := smtpd.ListenAndServeSTARTTLS(
    "127.0.0.1:587",
    "/path/to/server.crt",
    "/path/to/server.key",
    mailHandler,
    "MyServer",
    "mail.example.com",
)
```

Implicit TLS listener (SMTPS-style):

```go
err := smtpd.ListenAndServeTLSImplicit(
    "127.0.0.1:465",
    "/path/to/server.crt",
    "/path/to/server.key",
    mailHandler,
    "MyServer",
    "mail.example.com",
)
```

If you need encrypted private keys, use `Server.ConfigureTLSWithPassphrase`.

## Authentication

Provide an `AuthHandler` to enable AUTH.

```go
authHandler := func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
    return string(username) == "valid" && string(password) == "password", nil
}

srv := &smtpd.Server{
    Addr:         "127.0.0.1:2525",
    Appname:      "MyServer",
    AuthHandler:  authHandler,
    AuthRequired: true,
    Handler:      mailHandler,
}

if err := srv.ListenAndServe(); err != nil {
    log.Fatal(err)
}
```

Notes:

- By default, LOGIN and PLAIN are only offered over TLS.
- You can override allowed mechanisms with `AuthMechs` (for example in tests).
- If both TLS and auth are required, TLS requirements are enforced first.

## Recipient And VRFY Hooks

```go
srv := &smtpd.Server{
    Addr:    "127.0.0.1:2525",
    Handler: mailHandler,
    HandlerRcpt: func(_ net.Addr, from, to string) bool {
        _ = from
        return strings.HasSuffix(strings.ToLower(to), "@mail.example.com")
    },
    HandlerVrfy: func(_ net.Addr, address string) (string, bool) {
        if strings.EqualFold(address, "alias@example.com") {
            return "recipient@example.com", true
        }
        return "", false
    },
}
```

`HandlerVrfy` is checked first for `VRFY`. If it is not set, `HandlerRcpt` is used as a fallback policy.

## Server Configuration

Main `Server` options used in practice:

- `Addr`, `Appname`, `Hostname`
- `Handler` or `MsgIDHandler`
- `TLSConfig`, `TLSRequired`, `TLSListener`
- `AuthHandler`, `AuthRequired`, `AuthMechs`
- `HandlerRcpt`, `HandlerVrfy`
- `MaxSize`, `MaxRecipients`, `Timeout`
- `DisableReverseDNS`, `XClientAllowed`

Graceful lifecycle helpers:

- `Close()` to stop accepting new work immediately.
- `Shutdown(ctx)` to stop listeners and wait for open sessions.

## Testing

Run all tests:

```bash
go test ./...
```

The test suite covers command handling, TLS behavior, auth flows, size and line limits, shutdown semantics, parsing of extended SMTP parameters.

## Licensing

The project is primarily released under [The Unlicense](https://unlicense.org) (see [LICENSE](LICENSE)).

Some code was originally copied or adapted from [bradfitz/go-smtpd](https://github.com/bradfitz/go-smtpd). Those parts remain subject to the original upstream license terms where applicable.

## History

- The original SMTP server implementation was created in [bradfitz/go-smtpd](https://github.com/bradfitz/go-smtpd).
- In 2014, [Mark Hale](https://github.com/mhale) started [mhale/smtpd](https://github.com/mhale/smtpd), expanding RFC compliance, tests, TLS, auth, and maintainability.
- Over time, contributors added features such as configurable limits, graceful shutdown, reverse-DNS controls, message-id handler support, and XCLIENT support.
- In this fork, development continues at [sibexico/smtpd](https://github.com/sibexico/smtpd), including recent protocol and TLS hardening work (for example STARTTLS-required helper, VRFY improvements, stricter MAIL/RCPT parameter parsing, DSN parameter handling, etc).
