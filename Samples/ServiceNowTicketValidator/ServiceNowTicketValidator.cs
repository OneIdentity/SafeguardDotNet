// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator
{
    using System;
    using System.Security;

    using global::ServiceNowTicketValidator.DTOs;

    using Serilog;

    internal enum ValidationResult
    {
        Ignore,
        Approve,
        Deny,
    }

    internal class ServiceNowTicketValidator : IDisposable
    {
        private readonly ServiceNowClient _client;

        public ServiceNowTicketValidator(
            string dnsName,
            SecureString clientSecret,
            string userName,
            SecureString password)
        {
            // This ticket validator is specifically written for working with ServiceNow, but it could easily be modified
            // to support any ticketing system that you would like, even ticket systems that are not REST API based.
            // Just use a different client here and use a different ticket number lookup below.
            _client = new ServiceNowClient($"https://{dnsName}/", clientSecret, userName, password);
        }

        public ValidationResult CheckTicket(string ticketNumber, AccessRequest accessRequest)
        {
            var incident = _client.GetIncident(ticketNumber);
            if (incident == null)
            {
                Log.Information("Unable to locate incident {TicketNumber}, ignoring", ticketNumber);
                return ValidationResult.Ignore;
            }

            // If you would like to change the validation logic of a ticket this is where you would put your code changes.
            // Just delete the logic that is here and replace it with your own.
            var assignedUser = _client.GetSystemUser(incident.assigned_to.link);
            if (assignedUser?.name == null)
            {
                Log.Information(
                    "Unable to determine the assigned user for {TicketNumber} based on {ServiceNowLink}",
                    ticketNumber,
                    incident.assigned_to.link);
                return ValidationResult.Ignore;
            }

            var configurationItem = _client.GetConfigurationItem(incident.cmdb_ci.link);
            if (configurationItem?.name == null)
            {
                Log.Information(
                    "Unable to determine the configuration item for {TicketNumber} based on {ServiceNowLink}",
                    ticketNumber,
                    incident.assigned_to.link);
                return ValidationResult.Ignore;
            }

            if (assignedUser.name != accessRequest.RequesterDisplayName)
            {
                Log.Information(
                    "Access request denied because requester ({Requester}) does not match ticket assignee ({Assignee})",
                    accessRequest.RequesterDisplayName,
                    assignedUser.name);
                return ValidationResult.Deny;
            }

            if (configurationItem.name != accessRequest.AssetName)
            {
                Log.Information(
                    "Access request denied because request target ({Requester}) does not match ticket configuration item ({Assignee})",
                    accessRequest.AssetName,
                    configurationItem.name);
                return ValidationResult.Deny;
            }

            return ValidationResult.Approve;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _client?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
