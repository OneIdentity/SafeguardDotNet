// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    using System;
    using System.Diagnostics.CodeAnalysis;

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowToken
    {
        private int _expires_in;

        public string access_token { get; set; }

        public string refresh_token { get; set; }

        public string scope { get; set; }

        public string token_type { get; set; }

        public int expires_in
        {
            get => _expires_in;
            set
            {
                _expires_in = value;
                ExpiresAt = DateTime.UtcNow.AddSeconds(value);
            }
        }

        public DateTime ExpiresAt { get; set; }

        public bool Expired => DateTime.UtcNow > ExpiresAt;
    }
}
