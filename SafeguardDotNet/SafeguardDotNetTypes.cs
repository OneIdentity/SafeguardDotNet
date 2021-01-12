using System;
using System.Collections.Generic;
using System.Net;
using System.Security;
using Newtonsoft.Json;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// Service identifiers for the different services in the Safeguard API.
    /// </summary>
    public enum Service
    {
        /// <summary>
        /// The core service contains all general cluster-wide Safeguard operations.
        /// </summary>
        Core,
        /// <summary>
        /// The appliance service contains appliance-specific Safeguard operations.
        /// </summary>
        Appliance,
        /// <summary>
        /// The notification service contains unauthenticated Safeguard operations.
        /// </summary>
        Notification,
        /// <summary>
        /// The a2a service contains application integration Safeguard operations.  It is called via the Safeguard.A2A class.
        /// </summary>
        A2A
    };

    /// <summary>
    /// A limited list of methods supported by the Safeguard API. Not all HTTP methods are supported.
    /// </summary>
    public enum Method
    {
        Post,
        Get,
        Put,
        Delete
    }

    /// <summary>
    /// A simple class for returning extended information from a Safeguard API method call.
    /// </summary>
    public class FullResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public IDictionary<string, string> Headers { get; set; }
        public string Body { get; set; }
    }

    /// <summary>
    /// A list of private key formats supported by Safeguard.
    /// </summary>
    public enum KeyFormat
    {
        /// <summary>
        /// OpenSSH legacy PEM format
        /// </summary>
        OpenSsh,
        /// <summary>
        /// Tectia format for use with tools from SSH.com
        /// </summary>
        Ssh2,
        /// <summary>
        /// Putty format for use with PuTTY tools
        /// </summary>
        Putty
    }

    /// <summary>
    /// A class representing the asset accounts that can be used with A2A credential retrieval.
    /// </summary>
    public class A2ARetrievableAccount : IDisposable
    {
        public string ApplicationName { get; set; }
        public string Description { get; set; }
        public bool Disabled { get; set; }
        public SecureString ApiKey { get; set; }
        public int AssetId { get; set; }
        public string AssetName { get; set; }
        public string AssetNetworkAddress { get; set; }
        public string AssetDescription { get; set; }
        public int AccountId { get; set; }
        public string AccountName { get; set; }
        public string DomainName { get; set; }
        public string AccountType { get; set; }
        public string AccountDescription { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }

        public void Dispose()
        {
            ApiKey?.Dispose();
            ApiKey = null;
        }
    }
}
