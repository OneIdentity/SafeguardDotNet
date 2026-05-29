// Copyright (c) One Identity LLC. All rights reserved.

using System;
using System.Threading;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin;

using Serilog;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console()
    .CreateLogger();

if (args.Length < 1)
{
    await Console.Out.WriteLineAsync("Usage: SafeguardDotNetDeviceCodeLoginTester <appliance> [ignoreSsl]");
    return;
}

var appliance = args[0];
var ignoreSsl = args.Length > 1 && args[1].Equals("true", StringComparison.OrdinalIgnoreCase);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

try
{
    using var connection = await DeviceCodeLogin.ConnectAsync(
        appliance,
        new DeviceCodeLoginParameters
        {
            DisplayCallback = info =>
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
            },
        },
        ignoreSsl: ignoreSsl,
        cancellationToken: cts.Token);

    await Console.Out.WriteLineAsync("Successfully connected!");
    var me = connection.InvokeMethod(Service.Core, Method.Get, "Me");
    await Console.Out.WriteLineAsync($"Logged in as: {me}");
}
catch (OperationCanceledException)
{
    await Console.Error.WriteLineAsync("Operation cancelled.");
    Environment.ExitCode = 1;
}
catch (SafeguardDotNetException ex)
{
    await Console.Error.WriteLineAsync($"Error: {ex.Message}");
    if (ex.HasResponse)
    {
        await Console.Error.WriteLineAsync($"Response: {ex.Response}");
    }

    Environment.ExitCode = 1;
}
