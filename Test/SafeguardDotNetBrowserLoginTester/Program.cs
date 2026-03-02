// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetBrowserLoginTester;

using System;
using System.Collections.Generic;

using CommandLine;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.BrowserLogin;

using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

internal class Program
{
    internal class Options
    {
        [Option(
            'a',
            "Appliance",
            Required = true,
            HelpText = "IP address or hostname of Safeguard appliance")]
        public string Appliance { get; set; }

        [Option(
            'x',
            "Insecure",
            Required = false,
            Default = false,
            HelpText = "Ignore validation of Safeguard appliance SSL certificate")]
        public bool Insecure { get; set; }

        [Option(
            'V',
            "Verbose",
            Required = false,
            Default = false,
            HelpText = "Display verbose debug output")]
        public bool Verbose { get; set; }
    }

    private static void Execute(Options opts)
    {
        try
        {
            var config = new LoggerConfiguration();
            config.WriteTo.Console(outputTemplate: "{Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code);

            if (opts.Verbose)
            {
                config.MinimumLevel.Debug();
            }
            else
            {
                config.MinimumLevel.Information();
            }

            Log.Logger = config.CreateLogger();
            var connection = DefaultBrowserLogin.Connect(opts.Appliance, ignoreSsl: opts.Insecure);
            Log.Information(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
            Log.Information("Press any key to quit...");
            Console.ReadKey();
            connection.LogOut();
        }
#pragma warning disable CA1031 // Intentional top-level catch-all for error logging
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Log.Error(ex, "Fatal exception occurred");
            Log.Information("Press any key to quit...");
            Console.ReadKey();
            Environment.Exit(1);
        }
    }

    private static void HandleParseError(IEnumerable<Error> errors)
    {
        Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();
        Log.Error("Invalid command line options");
        Environment.Exit(1);
    }

    private static void Main(string[] args)
    {
        Parser.Default.ParseArguments<Options>(args)
            .WithParsed(Execute)
            .WithNotParsed(HandleParseError);
    }
}
