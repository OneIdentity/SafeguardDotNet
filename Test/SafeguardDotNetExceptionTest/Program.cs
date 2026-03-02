// Copyright (c) One Identity LLC. All rights reserved.

using System;
using System.Collections.Generic;
using System.Net;
using System.Security;

using CommandLine;

using OneIdentity.SafeguardDotNet;

using SafeguardDotNetExceptionTest;

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

void TestConnectExceptions(string appliance)
{
    Console.WriteLine("Test connect anonymous with bad host");
    try
    {
        using var connection = Safeguard.Connect("bad.dns.name", ignoreSsl: true);
        throw new InvalidOperationException("Bad host anonymous did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        // RestSharp will now return two different error messages on Windows for an invalid host.
        if (!string.Equals(
            ex.Message,
            "Unable to anonymously connect to bad.dns.name, Error: The requested name is valid, but no data of the requested type was found. The requested name is valid, but no data of the requested type was found.",
            StringComparison.Ordinal)
            && !string.Equals(
                ex.Message,
                "Unable to anonymously connect to bad.dns.name, Error: No such host is known. (bad.dns.name:443)",
                StringComparison.Ordinal))
        {
            throw;
        }

        if (ex.HttpStatusCode != null)
        {
            throw;
        }

        if (ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != null)
        {
            throw;
        }

        if (ex.ErrorMessage != null)
        {
            throw;
        }
    }

    Console.WriteLine("Test connect with bad host");
    try
    {
        using var connection = Safeguard.Connect("bad.dns.name", "local", "admin", "a".ToSecureString(), ignoreSsl: true);
        throw new InvalidOperationException("Bad host did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        // RestSharp will now return two different error messages on Windows for an invalid host.
        if (!string.Equals(
            ex.Message,
            "Unable to connect to RSTS to find identity provider scopes, Error: The requested name is valid, but no data of the requested type was found. The requested name is valid, but no data of the requested type was found.",
            StringComparison.Ordinal)
            && !string.Equals(
                ex.Message,
                "Unable to connect to RSTS to find identity provider scopes, Error: No such host is known. (bad.dns.name:443)",
                StringComparison.Ordinal))
        {
            throw;
        }

        if (ex.HttpStatusCode != null)
        {
            throw;
        }

        if (ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != null)
        {
            throw;
        }

        if (ex.ErrorMessage != null)
        {
            throw;
        }
    }

    Console.WriteLine("Test connect with unknown user");
    try
    {
        using var connection = Safeguard.Connect(appliance, "local", "thisisnevergonnabethere", "a".ToSecureString(), ignoreSsl: true);
        throw new InvalidOperationException("Unknown user did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
        {
            throw;
        }

        if (!ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != null)
        {
            throw;
        }

        if (ex.ErrorMessage is not "invalid_request" and not null)
        {
            throw;
        }
    }

    Console.WriteLine("Test connect with bad password");
    try
    {
        using var connection = Safeguard.Connect(appliance, "local", "admin", "a".ToSecureString(), ignoreSsl: true);
        throw new InvalidOperationException("Bad password did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
        {
            throw;
        }

        if (!ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != null)
        {
            throw;
        }

        if (ex.ErrorMessage is not "invalid_request" and not null)
        {
            throw;
        }
    }
}

void TestApiExceptions(ISafeguardConnection connection)
{
    Console.WriteLine("Test catching one with no response body");
    try
    {
        connection.InvokeMethod(Service.Core, Method.Get, "This/Does/nt/Exist");
        throw new InvalidOperationException("Nonexistent URL did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        if (ex.HttpStatusCode != HttpStatusCode.NotFound)
        {
            throw;
        }

        if (!ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != null)
        {
            throw;
        }

        if (ex.ErrorMessage != null)
        {
            throw;
        }
    }

    Console.WriteLine("Test catching one for bad request no filter");
    try
    {
        connection.InvokeMethod(
            Service.Core,
            Method.Get,
            "Me/AccessRequestAssets",
            parameters: new Dictionary<string, string>() { ["filter"] = "This eq 'broken'" });
        throw new InvalidOperationException("Bad filter did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
        {
            throw;
        }

        if (!ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != 70009)
        {
            throw;
        }

        if (!string.Equals(
            ex.ErrorMessage,
            "Invalid filter property - 'This' is not a valid filter property name.",
            StringComparison.Ordinal))
        {
            throw;
        }
    }

    Console.WriteLine("Test catching one with model state issues");
    try
    {
        connection.InvokeMethod(
            Service.Appliance,
            Method.Put,
            "NetworkInterfaces/X1",
            /*lang=json,strict*/
            "{\"Name\":\"X1\",\"LinkDuplex\":\"FakeValue\"}");
        throw new InvalidOperationException("Bad model state did not throw an exception");
    }
    catch (SafeguardDotNetException ex)
    {
        if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
        {
            throw;
        }

        if (!ex.HasResponse)
        {
            throw;
        }

        if (ex.ErrorCode != 70000)
        {
            throw;
        }

        if (!string.Equals(ex.ErrorMessage, "The request is invalid.", StringComparison.Ordinal))
        {
            throw;
        }
    }
}

void Execute(TestOptions opts)
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

        TestConnectExceptions(opts.Appliance);

        ISafeguardConnection connection;
        if (!string.IsNullOrEmpty(opts.Username))
        {
            using var password = HandlePassword(opts.ReadPassword);
            connection = Safeguard.Connect(
                opts.Appliance,
                opts.IdentityProvider,
                opts.Username,
                password,
                opts.ApiVersion,
                opts.Insecure);
        }
        else if (opts.Anonymous)
        {
            connection = Safeguard.Connect(opts.Appliance, opts.ApiVersion, opts.Insecure);
        }
        else
        {
            throw new InvalidOperationException("Must specify Anonymous or Username");
        }

        Log.Debug("Access Token Lifetime Remaining: {Remaining}", connection.GetAccessTokenLifetimeRemaining());

        TestApiExceptions(connection);

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

void HandleParseError(IEnumerable<Error> errors)
{
    Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();
    Log.Error("Invalid command line options");
    Environment.Exit(1);
}

Parser.Default.ParseArguments<TestOptions>(args)
.WithParsed(Execute)
.WithNotParsed(HandleParseError);
