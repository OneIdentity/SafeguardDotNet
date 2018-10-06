using System;
using System.Security;

namespace ServiceNowTicketValidator
{
    internal class ServiceNowTicketValidator : IDisposable
    {
        private readonly ServiceNowClient _client;

        public ServiceNowTicketValidator(string dnsName, SecureString clientSecret, string userName, SecureString password)
        {
            _client = new ServiceNowClient($"https://{dnsName}/", clientSecret, userName, password);
        }

        public bool CheckTicket(string ticketNumber)
        {
            var incident = _client.GetIncident(ticketNumber);




            return false;
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
