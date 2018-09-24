using System;
using System.Runtime.Serialization;

namespace OneIdentity.SafeguardDotNet
{
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

        public SafeguardDotNetException(string message, string response)
            : base(message)
        {
            Response = response;
        }

        protected SafeguardDotNetException
            (SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public string Response { get; }

        public bool HasResponse => Response != null;
    }
}
