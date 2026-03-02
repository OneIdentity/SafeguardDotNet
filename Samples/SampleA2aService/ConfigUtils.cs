// Copyright (c) One Identity LLC. All rights reserved.

namespace SampleA2aService;

using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

using Serilog;
using Serilog.Events;

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
            throw new InvalidOperationException($"Unable to start SampleA2aService with empty {description}.");
        }
        catch (ConfigurationErrorsException ex)
        {
            Log.Error(ex, "{Key} is required in App.Config", key);
            throw new InvalidOperationException($"Unable to start SampleA2aService without {description}.", ex);
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

    public static void ConfigureLogging()
    {
        var logConfig = new LoggerConfiguration().MinimumLevel.Debug().WriteTo.Console();
        var loggingDirectory = ReadSettingFromAppConfigIfPresent("LoggingDirectory");
        if (loggingDirectory != null)
        {
            if (!Path.IsPathRooted(loggingDirectory))
            {
                loggingDirectory = Path.Combine(Assembly.GetEntryAssembly().Location, loggingDirectory);
            }

            logConfig.WriteTo.File(Path.Combine(loggingDirectory, "SampleA2aService-{Date}.log"),
                LogEventLevel.Debug);
        }

        Log.Logger = logConfig.CreateLogger();
    }

    public static void CheckForDebugHook()
    {
#if DEBUG
        var debugBreak = ReadSettingFromAppConfigIfPresent("DebugBreak");
        if (bool.TryParse(debugBreak, out var waitForDebugger) && waitForDebugger)
        {
            while (!Debugger.IsAttached)
            {
                Task.Delay(TimeSpan.FromSeconds(2)).Wait();
                Log.Debug("Waiting for debugger to attach");
            }

            Debugger.Break();
            Log.Debug("Debugger attached");
        }
#endif
    }
}
