// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetAccessRequestBrokerTool
{
    internal static class StringEnhancements
    {
        public static bool IsNumeric(this string str)
        {
            return int.TryParse(str, out _);
        }
    }
}
