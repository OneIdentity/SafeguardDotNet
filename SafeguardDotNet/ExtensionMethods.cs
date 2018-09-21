using System;
using System.Globalization;
using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    internal static class ExtensionMethods
    {
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
                    throw new ArgumentOutOfRangeException(nameof(thisMethod), thisMethod, null);
            }
        }
    }
}
