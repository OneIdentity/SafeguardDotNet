using System.Diagnostics.CodeAnalysis;

namespace ServiceNowTicketValidator.DTOs
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class Incident
    {
        public string number { get; set; }
        public string state { get; set; }
        public bool Active => active != "false";
        public string active { get; set; }
        public string opened_at { get; set; }
        public string resolved_at { get; set; }
        public string closed_at { get; set; }
    }
}
