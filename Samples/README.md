# Samples Using SafeguardDotNet

The following are some projects that can be used to solve customer problems using
the Safeguard API.  These projects are meant to give you ideas on how you would
craft your own solutions.  The following projects also show the recommended way
to run an automated service as a certificate user using a client certificate
credential.  When done properly, this certificate can be enrolled via CSR directly
on the hosting machine so that the private key never leaves the box.  This is the
most secure automated Safeguard API authentication mechanism.

## Sample Projects

- [SampleA2aService](SampleA2aService)

  This project shows how to use app.config, TopShelf, and Serilog to build simple
  Windows service that can interact with Safeguard.  In this case, the service will
  listen to A2A for password to change then call a handler that can react to the
  change.  This sort of service could be used to update a password stored in a
  configuration file for a legacy application.

  This project was initially developed using Visual Studio Code.  It can be modified
  using either Visual Studio Code or Visual Studio 2017.  It targets .NET Core 2.1
  runtime.

- [ServiceNowTicketValidator](ServiceNowTicketValidator)

  By default, the Safeguard ServiceNow integration will only check for the existence
  of a ticket and do rudimentary checks on the state of the ticket.  This sample
  project creates a service that can run as a programmatic approver in your Safeguard
  policy to only approve access requests if the referenced ServiceNow ticket number
  references a ticket meeting a custom criteria.  This allows you to do advanced
  ticket validation.  This project also uses TopShelf and Serilog.  Configuration is
  also stored in an app.config.

  This project was initially developed using Visual Studio 2017.  It targets .NET
  Framework 4.6.2.  It can be modified to suit your needs.

## TLS Certificate Validation

Both sample `app.config` files ship with `SafeguardIgnoreSsl=true`. This setting
exists so the samples run out-of-the-box against **development appliances that
use self-signed TLS certificates**. It tells the SDK to skip Safeguard appliance
certificate validation when negotiating the TLS handshake.

**Disabling TLS validation removes the SDK's protection against man-in-the-middle
attacks.** Treat the default in these samples as a starting point for local
development only.

When you adapt a sample for a real deployment:

- **Production deployments must set `SafeguardIgnoreSsl=false`** in `app.config`
  (or omit the key and rely on the SDK default). The appliance certificate chain
  must then validate against the host's trusted root store.
- If the appliance uses an internal / private CA, **install that CA certificate
  in the host machine's trust store** (`Cert:\LocalMachine\Root` on Windows or
  the OS trust bundle on Linux/macOS) rather than disabling validation.
- For certificate pinning or other custom trust policies, supply a
  `RemoteCertificateValidationCallback` via the `Safeguard.Connect(...)`
  overloads that accept a validation callback, instead of setting
  `SafeguardIgnoreSsl=true`. Implement the pinning logic (e.g. compare against
  a known SPKI hash) inside that callback.
- Code review your sample fork: searching for `IgnoreSsl` /
  `SafeguardIgnoreSsl` / `-IgnoreSsl` should yield only configuration
  intentionally scoped to non-production environments.

The `SafeguardIgnoreSsl` flag is a developer convenience, not a deployment
default. Leaving it set to `true` in production is a security defect.
