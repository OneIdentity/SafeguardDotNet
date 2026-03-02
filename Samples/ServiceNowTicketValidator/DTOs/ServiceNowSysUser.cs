// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    using System.Diagnostics.CodeAnalysis;

    // There are more fields available. I trimmed out what I thought was most useful.
    // Anything could be added back of course.
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowSysUser
    {
        public string sys_id { get; set; }

        public string name { get; set; }

        public string user_name { get; set; }

        public string first_name { get; set; }

        public string middle_name { get; set; }

        public string last_name { get; set; }

        public string email { get; set; }

        public string manager { get; set; }
    }
}
