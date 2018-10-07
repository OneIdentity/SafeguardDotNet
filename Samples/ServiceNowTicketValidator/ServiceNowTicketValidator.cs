using System;
using System.Security;
using Serilog;
using ServiceNowTicketValidator.DTOs;

namespace ServiceNowTicketValidator
{
    internal enum ValidationResult
    {
        Ignore,
        Approve,
        Deny
    }

    internal class ServiceNowTicketValidator : IDisposable
    {
        private readonly ServiceNowClient _client;

        public ServiceNowTicketValidator(string dnsName, SecureString clientSecret, string userName, SecureString password)
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


            return ValidationResult.Ignore;
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
