// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    using System.Diagnostics.CodeAnalysis;

    // There are more fields available. I trimmed out what I thought was most useful.
    // Anything could be added back of course.
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowIncident
    {
        public string number { get; set; }

        public string state { get; set; }

        public bool Active => active != "false";

        public string active { get; set; }

        public string opened_at { get; set; }

        public string resolved_at { get; set; }

        public string closed_at { get; set; }

        public ServiceNowLink caller_id { get; set; }

        public ServiceNowLink opened_by { get; set; }

        public ServiceNowLink assigned_to { get; set; }

        public ServiceNowLink cmdb_ci { get; set; }
    }
}
