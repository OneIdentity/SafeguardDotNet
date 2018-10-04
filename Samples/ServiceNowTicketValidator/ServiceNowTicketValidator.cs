using System;
using System.Security;

namespace ServiceNowTicketValidator
{
    internal class ServiceNowTicketValidator : IDisposable
    {
        public ServiceNowTicketValidator(string userName, SecureString password)
        {
            // TODO:
        }

        public bool CheckTicket(string ticketNumber)
        {
            // TODO:
            return false;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // TODO:
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
