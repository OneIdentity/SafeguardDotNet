// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetPkceNoninteractiveLoginTester;

using System;
using System.Security;

using CommandLine;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin;

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
            'i',
            "IdentityProvider",
            Required = false,
            Default = "local",
            HelpText = "Safeguard identity provider to use for rSTS")]
        public string IdentityProvider { get; set; }

        [Option(
            'u',
            "Username",
            Required = true,
            HelpText = "Optional username to pre-fill in authorization URL")]
        public string Username { get; set; }

        [Option(
            'p',
            "ReadPassword",
            Required = false,
            Default = false,
            HelpText = "Read any required password from console stdin")]
        public bool ReadPassword { get; set; }

        [Option(
            'v',
            "ApiVersion",
            Required = false,
            Default = 4,
            HelpText = "Version of the Safeguard API to use")]
        public int ApiVersion { get; set; }

        [Option(
            'V',
            "Verbose",
            Required = false,
            Default = false,
            HelpText = "Display verbose debug output")]
        public bool Verbose { get; set; }
    }

    private static SecureString PromptForSecret(string name)
    {
        Console.Write($"{name}: ");
        var password = new SecureString();
        while (true)
        {
            var keyInput = Console.ReadKey(true);
            if (keyInput.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (keyInput.Key == ConsoleKey.Backspace)
            {
                if (password.Length <= 0)
                {
                    continue;
                }

                password.RemoveAt(password.Length - 1);
                Console.Write("\b \b");
            }
            else
            {
                password.AppendChar(keyInput.KeyChar);
                Console.Write("*");
            }
        }

        Console.Write(Environment.NewLine);
        return password;
    }

    private static SecureString HandlePassword(bool readFromStdin)
    {
        return readFromStdin ? Console.ReadLine().ToSecureString() : PromptForSecret("Password");
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

            ISafeguardConnection connection = null;
            Log.Information("Starting PKCE non-interactive authentication flow...");
            Log.Information("Connecting to Safeguard...");
            Log.Information("Identity Provider: {IdentityProvider}", opts.IdentityProvider);
            Log.Information("Username: {Username}", opts.Username);
            using var password = HandlePassword(opts.ReadPassword);
            connection = PkceNoninteractiveLogin.Connect(opts.Appliance, opts.IdentityProvider, opts.Username, password);

            if (connection != null)
            {
                Log.Information(string.Empty);
                Log.Information("Successfully connected to Safeguard!");
                Log.Information(string.Empty);
                Log.Information("Current user information:");
                Log.Information(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
                Log.Information(string.Empty);
                Log.Information("Press any key to disconnect and quit...");
                Console.ReadKey();
                connection.LogOut();
            }
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

    private static void Main(string[] args)
    {
        Parser.Default.ParseArguments<Options>(args)
            .WithParsed(Execute);
    }
}
