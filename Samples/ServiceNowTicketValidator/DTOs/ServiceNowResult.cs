using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace ServiceNowTicketValidator.DTOs
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowResult<T> where T : class
    {
        public IEnumerable<T> result { get; set; }
    }
}
