// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetDeviceCodeLoginTester;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using CommandLine;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin;

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

        [Option(
            "async",
            Required = false,
            Default = false,
            HelpText = "Use ConnectAsync with Ctrl+C cancellation support")]
        public bool Async { get; set; }

        [Option(
            'n',
            "NonInteractive",
            Required = false,
            Default = false,
            HelpText = "Skip the post-success key press and emit structured device-code data for automation")]
        public bool NonInteractive { get; set; }
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

            ISafeguardConnection connection;
            if (opts.Async)
            {
                connection = ExecuteAsync(opts).GetAwaiter().GetResult();
            }
            else
            {
                connection = DeviceCodeLogin.ConnectAsync(
                    opts.Appliance,
                    BuildParameters(opts),
                    ignoreSsl: opts.Insecure).GetAwaiter().GetResult();
            }

            Log.Information("Successfully connected!");
            Log.Information(connection.InvokeMethod(Service.Core, Method.Get, "Me"));
            if (!opts.NonInteractive)
            {
                Log.Information("Press any key to quit...");
                Console.ReadKey();
            }

            connection.LogOut();
        }
#pragma warning disable CA1031 // Intentional top-level catch-all for error logging
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Log.Error(ex, "Fatal exception occurred");
            Environment.Exit(1);
        }
    }

    private static async Task<ISafeguardConnection> ExecuteAsync(Options opts)
    {
        using var cts = Safeguard.AgentBasedLoginUtils.CreateConsoleCancellationToken();
        Log.Information("Async mode: press Ctrl+C to cancel");
        return await DeviceCodeLogin.ConnectAsync(
            opts.Appliance,
            BuildParameters(opts),
            ignoreSsl: opts.Insecure,
            cancellationToken: cts.Token);
    }

    private static DeviceCodeLoginParameters BuildParameters(Options opts)
    {
        return new DeviceCodeLoginParameters
        {
            DisplayCallback = info =>
            {
                DisplayCallback(info);
                if (opts.NonInteractive)
                {
                    EmitStructuredDeviceCode(info);
                }
            },
        };
    }

    private static void EmitStructuredDeviceCode(DeviceCodeInfo info)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("verification_uri", info.VerificationUri);
            writer.WriteString("verification_uri_complete", info.VerificationUriComplete);
            writer.WriteString("user_code", info.UserCode);
            writer.WriteNumber("expires_in", info.ExpiresIn);
            writer.WriteEndObject();
        }

        Console.WriteLine($"DEVICE_CODE_DATA {Encoding.UTF8.GetString(stream.ToArray())}");
    }

    private static void DisplayCallback(DeviceCodeInfo info)
    {
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════");
        Console.WriteLine("  To sign in, open a browser and visit:");
        Console.WriteLine($"  {info.VerificationUriComplete}");
        Console.WriteLine();
        Console.WriteLine($"  Or go to: {info.VerificationUri}");
        Console.WriteLine($"  And enter code: {info.UserCode}");
        Console.WriteLine();
        Console.WriteLine($"  Code expires in {info.ExpiresIn} seconds.");
        Console.WriteLine("═══════════════════════════════════════════════════════");
        Console.WriteLine();
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
