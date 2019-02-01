# Samples Using SafeguardDotNet

The following are some projects that can be used to solve customer problems using
the Safeguard API.  These projects are meant to give you ideas on how you would
craft your own solutions.  The following projects also show the recommended way
to run an automated service as a certificate user using a client certificate
credential.  When done properly, this certificate can be enrolled via CSR directly
on the hosting machine so that the private key never leaves the box.  This is the
most secure automated Safeguard API authentication mechanism.

## Sample Projects

- SampleA2aService

  This project shows how to use app.config, TopShelf, and Serilog to build simple
  Windows service that can interact with Safeguard.  In this case, the service will
  listen to A2A for password to change then call a handler that can react to the
  change.  This sort of service could be used to update a password stored in a
  configuration file for a legacy application.

- ServiceNowTicketValidator

  By default, the Safeguard ServiceNow integration will only check for the existence
  of a ticket and do rudimentary checks on the state of the ticket.  This sample
  project creates a service that can run as a programmatic approver in your Safeguard
  policy to only approve access requests if the referenced ServiceNow ticket number
  references a ticket meeting a custom criteria.  This allows you to do advanced
  ticket validation.  This project also uses TopShelf and Serilog.  Configuration is
  also stored in an app.config.
