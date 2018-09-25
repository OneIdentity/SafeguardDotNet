using System;
using System.Globalization;
using System.Net;
using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// A few extension methods that are useful when calling SafeguardDotNet methods.
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Convenience method for easily converting standard strings to secure strings.
        /// </summary>
        /// <param name="thisString"></param>
        /// <returns>A secure string for storage in long-lived memory.</returns>
        public static SecureString ToSecureString(this string thisString)
        {
            // I realize this may defeat the purpose of using SecureStrings in the first place,
            // because the string was already in memory, but at least I tried.
            if (string.IsNullOrWhiteSpace(thisString))
                return null;
            var result = new SecureString();
            foreach (var c in thisString)
                result.AppendChar(c);
            return result;
        }

        /// <summary>
        /// Convenience method for easily converting secure strings to standard strings.
        /// </summary>
        /// <param name="thisSecureString"></param>
        /// <returns>A standard string that can be passed more easily to other methods.</returns>
        public static string ToInsecureString(this SecureString thisSecureString)
        {
            // I realize this may defeat the purpose of using SecureStrings in the first place,
            // because are dumping it back into memory, but at least there is the option to stay
            // secure.  Since the password comes back over the wire to the REST client the string
            // has already been in memory which sort of makes this all fruitless anyway.
            return new NetworkCredential(string.Empty, thisSecureString).Password;
        }
    }

    internal static class PrivateExtensionMethods
    {
        public static bool ContainsNoCase(this string thisString, string otherString)
        {
            return CultureInfo.InvariantCulture.CompareInfo.IndexOf(thisString, otherString,
                       CompareOptions.IgnoreCase) >= 0;
        }

        public static bool EqualsNoCase(this string thisString, string otherString)
        {
            return string.Equals(thisString, otherString, StringComparison.OrdinalIgnoreCase);
        }

        public static RestSharp.Method ConvertToRestSharpMethod(this Method thisMethod)
        {
            switch (thisMethod)
            {
                case Method.Post:
                    return RestSharp.Method.POST;
                case Method.Get:
                    return RestSharp.Method.GET;
                case Method.Put:
                    return RestSharp.Method.PUT;
                case Method.Delete:
                    return RestSharp.Method.DELETE;
                default:
                    throw new SafeguardDotNetException("Unknown Safeguard REST method",
                        new ArgumentOutOfRangeException(nameof(thisMethod), thisMethod, null));
            }
        }
    }
}
