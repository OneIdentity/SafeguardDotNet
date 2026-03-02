// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    using System.Diagnostics.CodeAnalysis;

    // There are more fields available. I trimmed out what I thought was most useful.
    // Anything could be added back of course.
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowCmdbCi
    {
        public string sys_id { get; set; }

        public string asset { get; set; }

        public string asset_tag { get; set; }

        public string model_number { get; set; }

        public string model_id { get; set; }

        public string serial_number { get; set; }

        public string sys_tags { get; set; }

        public string name { get; set; }

        public string fqdn { get; set; }

        public string dns_domain { get; set; }

        public string ip_address { get; set; }

        public string short_description { get; set; }

        public string operational_status { get; set; }

        public string owned_by { get; set; }

        public string managed_by { get; set; }

        public string checked_out { get; set; }

        public string department { get; set; }

        public string assigned_to { get; set; }
    }
}
