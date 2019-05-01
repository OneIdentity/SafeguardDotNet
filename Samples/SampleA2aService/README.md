TopShelf service that can be run to SampleA2aService .

This is built using the SafeguardDotNet nuget package from nuget.org, not using the source code from the repo.

This sample demonstrates:

- thumbprint-based client certificate authentication from a Windows host (most secure method)
- uses A2A for listening for password changes
- parameters are loaded from app.config
- Serilog logging goes to a console when run interactively and to rolling files when installed as a service


To test the sample:

Configure Safeguard
===================

If you already have a CA cert and SSL client certificate use those. If not,there are test certificates in the certs folder of the project. 

1. Log in to your Safeguard appliance as a user administrator. Create a new local user called a2a. On the authentication tab select "Certificate" specify the thumbprint: ec1c1c5862471c27925b9c7180eb4facf8398c58. On the permissions tab select "Auditor".
2. Log in to your Safeguard appliance as an appliance administrator and go to Settings -> Certificates -> Trusted Roots and add test-ca.crt as a Trusted Root.
3. Now go to External Integration -> Application to Application. Add a new registration called test. Select the a2a user. Select credential retrieval. On the Credential Retrieval tab select some accounts to monitor for password changes. If there are no accounts, you need to add some accounts first.
 

Configure the Sample A2A Service
================================
In Visual Studio, right click the SampleA2aService and select Publish. Click the Target Location link and copy the files to the machine where you want to run the service. On the machine where you will run the service:

1. Make sure that the dotnet core runtime 2.1 or higher is installed. 
2. Install test.full.pfx to Current User\Personal. The password is test123. Make sure to mark the checkbox for "Mark this key as exportable".
3. Locate the SampleA3aService.dll.config file and modify it as follows: (be sure to specify your safeguard network address)
```
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <appSettings>
        <add key="SafeguardAddress" value="<your network address>" />
        <add key="SafeguardClientCertificateThumbprint" value="ec1c1c5862471c27925b9c7180eb4facf8398c58" />
        <add key="SafeguardApiVersion" value="2" />
        <add key="SafeguardIgnoreSsl" value="true" />
        <add key="LoggingDirectory" value="Logs" />
    </appSettings>
</configuration>
```
4. Start the service from the command line: `dotnet SampleA2aService.dll`
