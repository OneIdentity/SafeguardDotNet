TopShelf service that can be run to perform legitimate ticket validation on ServiceNow tickets.

This is built using the SafeguardDotNet nuget package from nuget.org, not using the source code from the repo.

The current sample makes sure that the configuration item in the ticket matches the asset requested.
It also makes sure that the requester is the same as the assignee on the ticket.

This sample demonstrates:

- thumbprint-based client certificate authentication from a Windows host (most secure method)
- uses A2A for fetching credential to talk to ServiceNow
- uses client certificate and standard Safeguard API connection to act as automated approver
- uses persistent event listener to detect approval pending events
- parameters are loaded from app.config
- Serilog logging goes to a console when run interactively and to rolling files when installed as a service
