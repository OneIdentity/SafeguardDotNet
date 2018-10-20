using System;

namespace OneIdentity.SafeguardDotNet.A2A
{
    public enum AccessRequestType
    {
        Password,
        Ssh,
        Rdp
    }

    public class BrokeredAccessRequest
    {
        public AccessRequestType RequestType { get; set; }

        public string ForUserName { get; set; }
        public string ForUserIdentityProvider { get; set; }
        public int ForUserId { get; set; }

        public string AssetName { get; set; }
        public int AssetId { get; set; }

        public string AccountName { get; set; }
        public string AccountAssetName { get; set; }
        public string AccountId { get; set; }

        public bool IsEmergency { get; set; }

        public string ReasonCode { get; set; }
        public int ReasonCodeId { get; set; }
        public string ReasonComment { get; set; }

        public string TicketNumber { get; set; }

        public DateTime RequestedFor { get; set; }
        public TimeSpan RequestedDuration { get; set; }
    }
}
