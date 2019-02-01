TopShelf service that can be run to perform legitimate ticket validation on ServiceNow tickets.

This is built using the SafeguardDotNet nuget package from nuget.org, not using the source code from the repo.

This sample demonstrates:

- thumbprint-based client certificate authentication from a Windows host (most secure method)
- uses A2A for listening for password changes
- parameters are loaded from app.config
- Serilog logging goes to a console when run interactively and to rolling files when installed as a service
