// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator
{
    using System;
    using System.Configuration;

    using Serilog;

    internal static class ConfigUtils
    {
        public static string ReadRequiredSettingFromAppConfig(string key, string description)
        {
            try
            {
                var value = ConfigurationManager.AppSettings[key];
                if (!string.IsNullOrEmpty(value))
                {
                    return value;
                }

                Log.Error("{Key} is required in App.Config", key);
                throw new InvalidOperationException($"Unable to start ServiceNowTicketValidator with empty {description}.");
            }
            catch (ConfigurationErrorsException ex)
            {
                Log.Error(ex, "{Key} is required in App.Config", key);
                throw new InvalidOperationException($"Unable to start ServiceNowTicketValidator without {description}.", ex);
            }
        }

        public static string ReadSettingFromAppConfigIfPresent(string key)
        {
            try
            {
                var value = ConfigurationManager.AppSettings[key];
                return !string.IsNullOrEmpty(value) ? value : null;
            }
            catch (ConfigurationErrorsException)
            {
                return null;
            }
        }
    }
}
