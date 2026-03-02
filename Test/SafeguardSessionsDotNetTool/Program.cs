// Copyright (c) One Identity LLC. All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;

using CommandLine;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.Sps;

using SafeguardSessionsDotNetTool;

using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

void Execute(ToolOptions options)
{
    InitializeLogger(options);
    try
    {
        Log.Debug("Connecting to sps.");
        var connection = SafeguardForPrivilegedSessions.Connect(
            options.Address,
            options.Username,
            options.Password.ToSecureString(),
            options.Insecure);

        string responseBody;
        if (!string.IsNullOrEmpty(options.File))
        {
            responseBody = File.ReadAllText(options.File);
        }
        else
        {
            responseBody = options.Body;
        }

        Log.Debug("Invoking method on sps.", options.Method, options.RelativeUrl, responseBody);

        var result = connection.InvokeMethodFull(
            options.Method,
            options.RelativeUrl,
            options.Body);

        Console.Write(result.Body);
    }
#pragma warning disable CA1031 // Intentional top-level catch-all for error logging
    catch (Exception ex)
#pragma warning restore CA1031
    {
        Log.Error(ex, "Fatal exception occurred");
        Environment.Exit(1);
    }
}

void HandleParseError(IEnumerable<Error> errors)
{
    Log.Error("Invalid command line options");
    Environment.Exit(1);
}

void InitializeLogger(ToolOptions options)
{
    var config = new LoggerConfiguration();
    config.WriteTo.Console(outputTemplate: "{Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code);
    if (options.Verbose)
    {
        config.MinimumLevel.Debug();
    }
    else
    {
        config.MinimumLevel.Information();
    }

    Log.Logger = config.CreateLogger();
    Log.Debug("Logger initialized.");
}

Parser.Default.ParseArguments<ToolOptions>(args)
.WithParsed(Execute)
.WithNotParsed(HandleParseError);
