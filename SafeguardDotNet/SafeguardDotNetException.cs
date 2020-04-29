using System;
using System.Net;
using System.Runtime.Serialization;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This class extends the base Exception class with a SafeguardDotNet specific exception.
    /// SafeguardDotNet tries to throw all exception using this class. SafeguardDotNet throws
    /// exceptions when 1) it fails to make call, 2) fails to parse or handle data, 3) when a
    /// Safeguard API endpoint returns a non-success status code. When response data is
    /// available, it is populated in the Response property in this class.
    /// </summary>
    public class SafeguardDotNetException : Exception
    {

        public SafeguardDotNetException()
            : base("Unknown SafeguardDotNetException")
        {
        }

        public SafeguardDotNetException(string message)
            : base(message)
        {
        }

        public SafeguardDotNetException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public SafeguardDotNetException(string message, HttpStatusCode httpStatusCode, string response)
            : base(message)
        {
            HttpStatusCode = httpStatusCode;
            Response = response;
            if (JToken.Parse(Response) is JObject responseObj &&
                responseObj.TryGetValue("Code", StringComparison.OrdinalIgnoreCase, out var value))
            {
                if (int.TryParse(value.ToString(), out var code))
                    ErrorCode = code;
            }
        }

        protected SafeguardDotNetException
            (SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        /// <summary>
        /// HTTP status code returned from Safeguard API as part of the failure.
        /// </summary>
        public HttpStatusCode? HttpStatusCode { get; }

        /// <summary>
        /// Response error code returned from Safeguard API as part of the failure.
        /// </summary>
        public int? ErrorCode { get; }

        /// <summary>
        /// Response data returned from Safeguard API as part of the failure.
        /// </summary>
        public string Response { get; }

        /// <summary>
        /// Whether or not this exception contains response data.
        /// </summary>
        public bool HasResponse => Response != null;
    }
}
