using System.Collections.Generic;
using System.Net;

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
        public HttpStatusCode StatusCode;
        public IDictionary<string, string> Headers;
        public string Body;
    }
}
