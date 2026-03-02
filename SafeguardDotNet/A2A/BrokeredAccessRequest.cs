// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.A2A
{
    using System;

    using Newtonsoft.Json;

    /// <summary>
    /// Type of brokered access request to create.
    /// </summary>
    public enum BrokeredAccessRequestType
    {
        /// <summary>
        /// Access request is for a password.
        /// </summary>
        Password,
        /// <summary>
        /// Access request is for an SSH session.
        /// </summary>
        Ssh,
        /// <summary>
        /// Access request is for a remote desktop session.
        /// </summary>
        Rdp,
    }

    /// <summary>
    /// This class is used to define a brokered access request.
    /// </summary>
    public class BrokeredAccessRequest
    {
        /// <summary>
        /// The type of access request to create.
        /// </summary>
        [JsonConverter(typeof(AccessRequestTypeConverter))]
        public BrokeredAccessRequestType AccessType { get; set; }

        /// <summary>
        /// The name of the user to create the access request for. If the <see cref="ForUserId"/> property is
        /// set, then this property will be ignored.
        /// </summary>
        public string ForUserName { get; set; }

        /// <summary>
        /// The name of the identity provider to create the access request for. If the <see cref="ForUserId"/>
        /// property is set, then this property will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "ForProvider")]
        public string ForUserIdentityProvider { get; set; }

        /// <summary>
        /// The ID of the user to create the access request for.
        /// </summary>
        public int? ForUserId { get; set; }

        /// <summary>
        /// The name of the asset to create the access request for. If the <see cref="AssetId"/> property is
        /// set, then this property will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "SystemName")]
        public string AssetName { get; set; }

        /// <summary>
        /// The ID of the asset to create the access request for.
        /// </summary>
        [JsonProperty(PropertyName = "SystemId")]
        public int? AssetId { get; set; }

        /// <summary>
        /// The name of the account to create the access request for. If the <see cref="AccountId"/> property is
        /// set, then this property will be ignored.
        /// </summary>
        public string AccountName { get; set; }

        /// <summary>
        /// The ID of the account to create the access request for.
        /// </summary>
        public int? AccountId { get; set; }

        /// <summary>
        /// The name of the asset the account is from to create the access request for. If the
        /// <see cref="AccountAssetId"/> property is set, then this property will be ignored.
        /// </summary>
        [JsonProperty(PropertyName = "AccountSystemName")]
        public string AccountAssetName { get; set; }

        /// <summary>
        /// The ID of the asset the account is from to create the access request for.
        /// </summary>
        [JsonProperty(PropertyName = "AccountSystemId")]
        public int? AccountAssetId { get; set; }

        /// <summary>
        /// Whether or not this is an emergency access request.
        /// </summary>
        public bool IsEmergency { get; set; }

        /// <summary>
        /// The name of the pre-defined reason code to include in the access request. If the <see cref="ReasonCodeId"/>
        /// property is set, then this property will be ignored.
        /// </summary>
        public string ReasonCode { get; set; }

        /// <summary>
        /// The ID of the pre-defined reason code to include in the access request.
        /// </summary>
        public int? ReasonCodeId { get; set; }

        /// <summary>
        /// A reason comment to include in the access request.
        /// </summary>
        public string ReasonComment { get; set; }

        /// <summary>
        /// A ticket number associated with the new access request.
        /// </summary>
        public string TicketNumber { get; set; }

        /// <summary>
        /// The time when the access request should be requested for. All values will be converted to UTC date and time
        /// before being sent to the server.
        /// </summary>
        [JsonConverter(typeof(UtcDateTimeConverter))]
        public DateTime? RequestedFor { get; set; }

        /// <summary>
        /// The amount of time the access request should be requested for.
        /// </summary>
        [JsonConverter(typeof(CustomTimeSpanConverter))]
        public TimeSpan? RequestedDuration { get; set; }

        public int? RequestedDurationDays => RequestedDuration?.Days;

        public int? RequestedDurationHours => RequestedDuration?.Hours;

        public int? RequestedDurationMinutes => RequestedDuration?.Minutes;
    }

    /// <summary>
    /// Simple JSON converter for dealing with brokered access request type enumeration.
    /// </summary>
    public class AccessRequestTypeConverter : JsonConverter<BrokeredAccessRequestType>
    {
        public override void WriteJson(JsonWriter writer, BrokeredAccessRequestType value, JsonSerializer serializer)
        {
            switch (value)
            {
                case BrokeredAccessRequestType.Password:
                    writer.WriteValue("Password");
                    break;
                case BrokeredAccessRequestType.Ssh:
                    writer.WriteValue("SSH");
                    break;
                case BrokeredAccessRequestType.Rdp:
                    writer.WriteValue("RemoteDesktop");
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(value), value, null);
            }
        }

        public override BrokeredAccessRequestType ReadJson(
            JsonReader reader,
            Type objectType,
            BrokeredAccessRequestType existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            var value = (string)reader.Value;
            if (value.EqualsNoCase("Password"))
            {
                return BrokeredAccessRequestType.Password;
            }

            if (value.EqualsNoCase("SSH"))
            {
                return BrokeredAccessRequestType.Ssh;
            }

            if (value.EqualsNoCase("RemoteDesktop"))
            {
                return BrokeredAccessRequestType.Rdp;
            }

            throw new SafeguardDotNetException($"Unknown access request type \"{value}\"");
        }
    }

    /// <summary>
    /// Simple JSON converter for UTC date times.
    /// </summary>
    public class UtcDateTimeConverter : JsonConverter<DateTime>
    {
        public override void WriteJson(JsonWriter writer, DateTime value, JsonSerializer serializer)
        {
            var utc = value.ToUniversalTime();
            writer.WriteValue(utc.ToString("u"));
        }

        public override DateTime ReadJson(
            JsonReader reader,
            Type objectType,
            DateTime existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            return DateTime.Parse((string)reader.Value, System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    public class CustomTimeSpanConverter : JsonConverter<TimeSpan>
    {
        public override void WriteJson(JsonWriter writer, TimeSpan value, JsonSerializer serializer)
        {
            writer.WriteValue($"{value.Days}:{value.Hours}:{value.Minutes}");
        }

        public override TimeSpan ReadJson(
            JsonReader reader,
            Type objectType,
            TimeSpan existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            var spanstr = (string)reader.Value;
            if (spanstr != null)
            {
                var fields = spanstr.Split(':');
                if (fields.Length < 3)
                {
                    throw new SafeguardDotNetException($"Unexpected timespan value \"{spanstr}\"");
                }

                return new TimeSpan(int.Parse(fields[0]), int.Parse(fields[1]), int.Parse(fields[2]));
            }

            return TimeSpan.Zero;
        }
    }
}
