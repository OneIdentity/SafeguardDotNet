using System;
using System.Configuration;
using Serilog;

namespace SampleA2aService
{
    static class ConfigUtils
    {
        public static string ReadRequiredSettingFromAppConfig(string key, string description)
        {
            try
            {
                var value = ConfigurationManager.AppSettings[key];
                if (!string.IsNullOrEmpty(value))
                    return value;
                Log.Error($"{key} is required in App.Config");
                throw new Exception($"Unable to start ServiceNowTicketValidator with empty {description}.");
            }
            catch (ConfigurationErrorsException ex)
            {
                Log.Error(ex, $"{key} is required in App.Config");
                throw new Exception($"Unable to start ServiceNowTicketValidator without {description}.", ex);
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
