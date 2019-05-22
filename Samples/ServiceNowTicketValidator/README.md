Sample ServiceNow Ticket Validator Service
==========================================

TopShelf service that can be run to perform legitimate ticket validation on ServiceNow tickets.

This is built using the SafeguardDotNet nuget package from nuget.org, not using the source code from
this repository.

This service in this sample functions as an approver in Safeguard policy to approve access requests
if the ServiceNow 'Configuration item' on the ticket matches the requested Asset that the requested
Account belongs to and the ServiceNow ticket 'Assigned to' user matches the requesting Safeguard User.

In addition, Safeguard is used to store the ServiceNow credentials for reading ticket information from
ServiceNow.  Safeguard A2A is used to securely release this credential.

[Custom Integration with ServiceNow video](https://www.youtube.com/watch?v=C9crR_KcE0g)

[![Custom Integration with ServiceNow video](https://img.youtube.com/vi/C9crR_KcE0g/0.jpg)](https://www.youtube.com/watch?v=C9crR_KcE0g)

Setup
=====

### ServiceNow Setup

1. Create a user in ServiceNow who has sufficient access to read ticket details from the ServiceNow.
Record this user’s username and password as it is used in multiple places hereafter. We will refer to
this user as `ServiceNowReadUser` in future references. 

2. Create another user in ServiceNow. This user will be used in the "Assigned to" field when we create
an incident in ServiceNow. We will refer to this user as `ServiceNowTicketAssigneeUser`.

3. Create an active incident. Make sure that the incident has valid entries in the "configuration item"
and "Assigned to" fields. The "Configuration item" field will need to map to a Safeguard Asset. We will
refer to this Asset as `RequestAsset`. The "Assigned to" field needs to be the `ServiceNowTicketAssigneeUser`.
Record this incident number, we will refer to this incident number later as `IncidentNumber`.

### Client Certificate Setup

1. Generate a client certificate and private key on the host that will run the service.  Make sure this
client certificate and private key are installed in the "Personal" store of the user that will run the
service.

2. Make sure that the client certificate is signed by a CA for which you have the certificate trust chain.
You will need to upload the CA certificates in the trust chain to Safeguard as trusted certificates.

3. Note the client certificate’s thumbprint as `A2AUserCertificateThumbprint` to use later.  To view the
thumbprint for the client certificate, run:

```Powershell
PS> Get-ChildItem Cert:\CurrentUser\My
```

### Safeguard Setup

#### Assets and Accounts

1. Create a Safeguard Asset with platform set to "Other" -- this will represent your ServiceNow instance.
Add to this Asset an Account whose name is the same as the `ServiceNowReadUser`.  Set the Account's
password to `ServiceNowReadUser`'s password so that it can properly authenticate to ServiceNow.

2. Create another Safeguard Asset for testing with the same name as `RequestAsset` listed in the
"Configuration item" field of your incident in ServiceNow.  Add to this Asset an Account that this sample
application will be approving access to.  This Account can have any name.  Note the name of this Account
as `RequestAccountName` to be used later.  Set this Account's password, or if this Account represents a
real Account on a real Asset, you can simply allow Safeguard to begin managing this Account's password.

#### Users

1. Create a Safeguard User with any name of your choice.  Configure this user to use "Certificate"
authentication and set the User's thumbprint to be `A2AUserCertificateThumbprint`, matching the thumbprint
from your client certificate.  This User does not need any Safeguard administrator permissions.  This
User will represent your A2A application and will act as a Safeguard approver to approve requests only
when the details listed in the ServiceNow incident match the details of the access request, thus performing
proper ticket validation.  Note this User's username as `SafeguardA2AUserUsername` to be used later.

2. Create another Safeguard User whose username matches `ServiceNowTicketAssigneeUser`.  This User can
be from any identity provider and use any supported type of authentication, but you must be able to
successfully sign into Safeguard with this user to run the sample.  This User does not need any Safeguard
administrator permissions.  This User will act as a requester and request access to an account needed to
address an incident in ServiceNow.  Note this User's username and password.  We will refer to this User
later as `SafeguardRequester`.

#### Ticket System

1. Under Settings -> External Integration -> Ticketing, add a ticketing system with any
name.  Make sure that the type is set to "Service Now".  Enter in the correct URL of your ServiceNow
instance.  Enter a valid username and password.  You may use `ServiceNowReadUser` for this, but you don't
have to.

#### Policy

1. Create a new Entitlement in Safeguard with any name.  Add to this Entitlement an Access Policy with
any name.  On the "Scope" tab, add the Account whose name matches `RequestAccountName`.  On the "Requester"
tab, ensure that "Require Ticket Number" is checked.  On the "Approver" tab, ensure that "Approvals
Required" is selected.  Add the User whose name matches `SafeguardA2AUserUsername` as the required approver.
Fill in other information on the Access Policy as appropriate.

#### A2A

1. Under Settings -> Appliance -> Enable or Disable Services, make sure that "Application to Application"
is enabled.

2. Under Settings -> External Integration -> Application to Application, add an A2A Registration.  This
A2A Registration may have any name.  For "Certificate User", select the User whose name matches
`SafeguardA2AUserUsername`.  Check the box to configure this A2A Registration for "Credential Retrieval".
On the "Credential Retrieval" tab, add the Safeguard Account whose name matches `ServiceNowReadUser` so
that this Account's password will be released to the sample application.  After creating the A2A
Registration, select the credential retrieval from the table and click the (key icon).  Copy the API key
corresponding to the Account whose name matches `ServiceNowReadUser`.  Note this API key as
`ServiceNowA2AAccountAPIKey` to be used later.

#### Sample Application Setup (app.config)

There are several fields of the app.config file of this sample that need to be populated:

| Key | Comment or Value |
| - | - |
| SafeguardAddress | IP address of the appliance |
| SafeguardClientCertificateThumbprint |  |
| SafeguardApiVersion | 3 |
| SafeguardIgnoreSsl | true (or false) |
| ServiceNowDnsName | IP address or host name to Service Now |
| ServiceNowClientSecret | Empty string for this sample |
| ServiceNowUserName | `ServiceNowReadUser` |
| SafeguardA2AApiKeyForServiceNowPassword | `ServiceNowA2AAccountAPIKey` |
| LoggingDirectory | Relative path from executable, ex. “Logs” |

Running the Sample
==================

This sample, ServiceNowTicketValidator, can be run as a console application or as a Windows service.

To run as a Windows service, run these commands from a shell:

```Powershell
PS> ServiceNowTicketValidator.exe install
PS> net start ServiceNowTicketValidator
```

This uses TopShelf to install the console application as a Windows service.

### Making a Request

Log in with the credentials for `SafeguardRequester` and create a new access request. On the
"Asset Selection" tab, select the Asset whose name matches `RequestAsset`. On the "Account & Access Type"
tab, select the Account whose name matches `RequestAccountName`. On the "Request Details" tab, enter
your `IncidentNumber` into the "Ticket Number" field. The Asset name will match `RequestAsset` entered
on the ServiceNow incident and your user display name will match `SafeguardRequester`, therefore your
access request will be immediately approved by the sample application on behalf of the User with username
`SafeguardA2AUserUsername`. Otherwise approval from this user is not given.

Notes
=====

This sample demonstrates a lot of integration functionality in Safeguard and demonstrates the secure
method for running an external integration application against Safeguard.  Using A2A and client
certificate authentication are the preferred methods for accessing the Safeguard API from an automated
process.  This same technique can be used in your own custom integrations and robotic process automations
(RPAs).  Using a client certificate securely enrolled via a secure certificate enrollment process where
the private key has never left the certificate store is the most secure option.

Using Safeguard Approver Groups, you may use the `SafeguardA2AUserUsername` ticket validator User in one
Approver Group and a separate Approver Group with human Safeguard Users to get the benefits of both
ticket validation and four-eyes approval of any access request.

The current sample makes sure that the "Configuration item" in the ticket matches the Asset requested.
It also makes sure that the requester is the same as the "Assigned to" on the ticket.  However, this
code could very easily be customized to any arbitrary ticket validation criteria.  There is a section
in the code in `ServiceNowTicketValidator.cs` that says:

```C#
// If you would like to change the validation logic of a ticket this is where you would put your code changes.
// Just delete the logic that is here and replace it with your own.
```

This is where you could customize this sample to suit your own ticket validation needs.





The sample can be updated to modify the ticket validation logic in order to fit the needs of any organization using ServiceNow.

This sample demonstrates:

- thumbprint-based client certificate authentication from a Windows host (most secure method)
- uses A2A for fetching credential to talk to ServiceNow
- uses client certificate and standard Safeguard API connection to act as automated approver
- uses persistent event listener to detect approval pending events
- parameters are loaded from app.config
- Serilog logging goes to a console when run interactively and to rolling files when installed as a service
