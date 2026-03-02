// Copyright (c) One Identity LLC. All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security;

using CommandLine;

using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.A2A;

using SafeguardDotNetA2aTool;

using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

SecureString PromptForSecret(string name)
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

SecureString HandlePassword(bool readFromStdin)
{
    return readFromStdin ? Console.ReadLine().ToSecureString() : PromptForSecret("Password");
}

ISafeguardA2AContext CreateA2AContext(ToolOptions opts)
{
    ISafeguardA2AContext context;
    if (!string.IsNullOrEmpty(opts.CertificateFile))
    {
        using var password = HandlePassword(opts.ReadPassword);
        if (opts.CertificateAsData)
        {
            var bytes = File.ReadAllBytes(opts.CertificateFile);
            context = Safeguard.A2A.GetContext(opts.Appliance, bytes, password, opts.ApiVersion, opts.Insecure);
        }
        else
        {
            context = Safeguard.A2A.GetContext(
                opts.Appliance,
                opts.CertificateFile,
                password,
                opts.ApiVersion,
                opts.Insecure);
        }
    }
    else if (!string.IsNullOrEmpty(opts.Thumbprint))
    {
        context = Safeguard.A2A.GetContext(opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
    }
    else
    {
        throw new InvalidOperationException("Must specify CertificateFile or Thumbprint");
    }

    return context;
}

void Execute(ToolOptions opts)
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

        using var context = CreateA2AContext(opts);
        if (opts.ApiKey.Equals("?", StringComparison.Ordinal))
        {
            var responseBody = context.GetRetrievableAccounts();
            foreach (var obj in responseBody)
            {
                Log.Information(obj.ToString());
            }
        }
        else
        {
            if (opts.RetrievableAccounts)
            {
                var accounts = context.GetRetrievableAccounts();
                Log.Information(System.Text.Json.JsonSerializer.Serialize(accounts));
            }

            if (opts.PrivateKey)
            {
                if (opts.PrivateKeyFile != null)
                {
                    var privateKey = File.ReadAllText(opts.PrivateKeyFile);
                    using var password = HandlePassword(opts.ReadPassword);
                    context.SetPrivateKey(opts.ApiKey.ToSecureString(), privateKey.ToSecureString(), password, opts.KeyFormat);
                }
                else
                {
                    using var responseBody = context.RetrievePrivateKey(opts.ApiKey.ToSecureString(), opts.KeyFormat);
                    Log.Information(responseBody.ToInsecureString());
                }
            }
            else if (opts.ApiKeySecret)
            {
                var responseBody = context.RetrieveApiKeySecret(opts.ApiKey.ToSecureString());
                foreach (var obj in responseBody)
                {
                    Log.Information(obj.ToString());
                }
            }
            else
            {
                if (opts.NewPassword)
                {
                    using var password = HandlePassword(opts.ReadPassword);
                    context.SetPassword(opts.ApiKey.ToSecureString(), password);
                }
                else
                {
                    using var responseBody = context.RetrievePassword(opts.ApiKey.ToSecureString());
                    Log.Information(responseBody.ToInsecureString());
                }
            }
        }
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
    Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();
    Log.Error("Invalid command line options");
    Environment.Exit(1);
}

Parser.Default.ParseArguments<ToolOptions>(args)
.WithParsed(Execute)
.WithNotParsed(HandleParseError);
