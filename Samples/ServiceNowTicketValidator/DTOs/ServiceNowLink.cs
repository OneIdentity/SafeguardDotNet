using System.Diagnostics.CodeAnalysis;

namespace ServiceNowTicketValidator.DTOs
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowLink
    {
        public string link { get; set; }
        public string value { get; set; }
    }
}
