// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator.DTOs
{
    // There are more fields available. I trimmed out what I thought was most useful.
    // I decided to remove all time-based data, but it could be added back.
    internal class AccessRequest
    {
        public string Id { get; set; }

        public bool IsEmergency { get; set; }

        public string State { get; set; }

        public string TicketNumber { get; set; }

        public string AccessRequestType { get; set; }

        public string AccountRequestType { get; set; }

        public int AssetId { get; set; }

        public string AssetName { get; set; }

        public string AssetNetworkAddress { get; set; }

        public int AccountId { get; set; }

        public string AccountName { get; set; }

        public string AccountDomainName { get; set; }

        public int AccountSystemId { get; set; }

        public string AccountSystemName { get; set; }

        public string ReasonCode { get; set; }

        public string ReasonComment { get; set; }

        public int RequestedDurationDays { get; set; }

        public int RequestedDurationHours { get; set; }

        public int RequestedDurationMinutes { get; set; }

        public int DurationInMinutes { get; set; }

        public string RequesterId { get; set; }

        public string RequesterDisplayName { get; set; }

        public string RequesterEmailAddress { get; set; }

        public int CurrentApprovalCount { get; set; }

        public int RequiredApprovalCount { get; set; }
    }
}
