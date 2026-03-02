// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetGuiTester
{
    using System;
    using System.Collections.Generic;

    using CommandLine;

    using OneIdentity.SafeguardDotNet;
    using OneIdentity.SafeguardDotNet.GuiLogin;

    using Serilog;
    using Serilog.Sinks.SystemConsole.Themes;

    internal static class Program
    {
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
                var connection = LoginWindow.Connect(opts.Appliance);
                Log.Information(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
                Log.Information("Press any key to quit...");
                Console.ReadKey();
                connection.LogOut();
            }
            catch (Exception ex)
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

        [STAThread]
        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
