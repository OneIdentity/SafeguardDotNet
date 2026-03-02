// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security;

    using Serilog;

    /// <summary>
    /// A few extension methods that are useful when calling SafeguardDotNet methods.
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Convenience method for easily converting standard strings to secure strings.
        /// </summary>
        /// <param name="thisString">The string to convert.</param>
        /// <returns>A secure string for storage in long-lived memory.</returns>
        /// <remarks>
        /// Note: Converting from a standard string to SecureString may not provide complete memory protection
        /// since the source string already exists in memory. This method is provided for convenience when
        /// working with APIs that require SecureString parameters.
        /// </remarks>
        public static SecureString ToSecureString(this string thisString)
        {
            // I realize this may defeat the purpose of using SecureStrings in the first place,
            // because the string was already in memory, but at least I tried.
            if (string.IsNullOrWhiteSpace(thisString))
            {
                return null;
            }

            var result = new SecureString();
            foreach (var c in thisString)
            {
                result.AppendChar(c);
            }

            return result;
        }

        /// <summary>
        /// Convenience method for easily converting secure strings to standard strings.
        /// </summary>
        /// <param name="thisSecureString">The SecureString to convert.</param>
        /// <returns>A standard string that can be passed more easily to other methods.</returns>
        /// <remarks>
        /// Warning: This method defeats the memory protection provided by SecureString by converting it back
        /// to a standard string. Use only when necessary for interoperability with APIs that require string
        /// parameters. The resulting string will remain in memory until garbage collected.
        /// </remarks>
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
            return CultureInfo.InvariantCulture.CompareInfo.IndexOf(
                thisString,
                otherString,
                CompareOptions.IgnoreCase) >= 0;
        }

        public static bool EqualsNoCase(this string thisString, string otherString)
        {
            return string.Equals(thisString, otherString, StringComparison.OrdinalIgnoreCase);
        }

        public static HttpMethod ConvertToHttpMethod(this Method thisMethod)
        {
            switch (thisMethod)
            {
                case Method.Post:
                    return HttpMethod.Post;
                case Method.Get:
                    return HttpMethod.Get;
                case Method.Put:
                    return HttpMethod.Put;
                case Method.Delete:
                    return HttpMethod.Delete;
                default:
                    throw new SafeguardDotNetException("Unknown Safeguard REST method",
                        new ArgumentOutOfRangeException(nameof(thisMethod), thisMethod, null));
            }
        }

        public static void LogResponseDetails(this FullResponse fullResponse)
        {
            if (fullResponse is null)
            {
                Log.Debug("LogResponseDetails: fullResponse is null!");
                return;
            }

            Log.Debug("Response status code: {ResponseStatusCode}", fullResponse.StatusCode);

            Log.Debug("  Response headers: {ResponseHeaders}",
                fullResponse.Headers?.Select(kv => $"{kv.Key}: {kv.Value}")
                    .Aggregate(string.Empty, (str, header) => $"{str}{header}, ").TrimEnd(',', ' '));

            Log.Debug("  Body size: {ResponseBodySize}", fullResponse.Body == null ? "None" : $"{fullResponse.Body.Length}");
        }

        public static void LogRequestDetails(this HttpRequestMessage requestMessage, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null)
        {
            if (requestMessage is null)
            {
                Log.Debug("LogRequestDetails: requestMessage is null!");
                return;
            }

            LogRequestDetails(requestMessage.Method, requestMessage.RequestUri.ToString(), parameters, additionalHeaders);
        }

        private static void LogRequestDetails(HttpMethod method, string uri, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null)
        {
            Log.Debug("Invoking method: {HttpMethod} {Uri}", method.ToString().ToUpper(), uri);

            Log.Debug("  Query parameters: {QueryParameters}",
                parameters?.Select(kv => $"{kv.Key}={kv.Value}").Aggregate(string.Empty, (str, param) => $"{str}{param}&")
                    .TrimEnd('&') ?? "None");

            Log.Debug("  Additional headers: {AdditionalHeaders}",
                additionalHeaders?.Select(kv => $"{kv.Key}: {kv.Value}")
                    .Aggregate(string.Empty, (str, header) => $"{str}{header}, ").TrimEnd(',', ' ') ?? "None");
        }
    }
}
