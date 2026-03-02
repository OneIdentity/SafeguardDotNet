// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    internal class AccessRequestApprovalPendingEvent
    {
        public string ApplianceId { get; set; }

        public string RequestId { get; set; }

        public int AssetId { get; set; }

        public string AssetName { get; set; }

        public int AccountId { get; set; }

        public string AccountName { get; set; }

        public string Requester { get; set; }

        public int RequesterId { get; set; }

        public string Comment { get; set; }

        public int DurationInMinutes { get; set; }
    }
}
