// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetTool;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.Json;
using System.Threading;

using CommandLine;

using OneIdentity.SafeguardDotNet;

using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

internal static class Program
{
    private static CancellationTokenSource Cts { get; } = new CancellationTokenSource();

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

    private static void Execute(ToolOptions opts)
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

            if (!opts.TokenLifetime && !opts.Logout && !opts.GetToken
                && string.IsNullOrEmpty(opts.RelativeUrl))
            {
                throw new ArgumentException("--Service, --Method, and --RelativeUrl are required for API invocation");
            }

            // Resolve BodyFile: read the file contents into Body
            if (!string.IsNullOrEmpty(opts.BodyFile))
            {
                opts.Body = File.ReadAllText(opts.BodyFile);
            }

            ISafeguardConnection connection;
            var minTls = ParseTlsVersion(opts.MinTlsVersion, "--MinTlsVersion");
            var maxTls = ParseTlsVersion(opts.MaxTlsVersion, "--MaxTlsVersion");
            if (!string.IsNullOrEmpty(opts.Username))
            {
                using var password = HandlePassword(opts.ReadPassword);
                connection = Safeguard.Connect(
                    opts.Appliance,
                    opts.IdentityProvider,
                    opts.Username,
                    password,
                    opts.ApiVersion,
                    opts.Insecure,
                    minTlsVersion: minTls,
                    maxTlsVersion: maxTls);
            }
            else if (!string.IsNullOrEmpty(opts.CertificateFile))
            {
                using var password = HandlePassword(opts.ReadPassword);
                if (opts.CertificateAsData)
                {
                    var bytes = File.ReadAllBytes(opts.CertificateFile);
                    connection = Safeguard.Connect(
                        opts.Appliance,
                        bytes,
                        password,
                        opts.ApiVersion,
                        opts.Insecure,
                        minTlsVersion: minTls,
                        maxTlsVersion: maxTls);
                }
                else
                {
                    connection = Safeguard.Connect(
                        opts.Appliance,
                        opts.CertificateFile,
                        password,
                        opts.ApiVersion,
                        opts.Insecure,
                        minTlsVersion: minTls,
                        maxTlsVersion: maxTls);
                }
            }
            else if (!string.IsNullOrEmpty(opts.Thumbprint))
            {
                connection = Safeguard.Connect(
                    opts.Appliance,
                    opts.Thumbprint,
                    opts.ApiVersion,
                    opts.Insecure,
                    minTlsVersion: minTls,
                    maxTlsVersion: maxTls);
            }
            else if (!string.IsNullOrEmpty(opts.AccessToken))
            {
                using var token = opts.AccessToken.ToSecureString();
                connection = Safeguard.Connect(
                    opts.Appliance,
                    token,
                    opts.ApiVersion,
                    opts.Insecure,
                    minTlsVersion: minTls,
                    maxTlsVersion: maxTls);
            }
            else if (opts.Anonymous)
            {
                connection = Safeguard.Connect(
                    opts.Appliance,
                    opts.ApiVersion,
                    opts.Insecure,
                    minTlsVersion: minTls,
                    maxTlsVersion: maxTls);
            }
            else
            {
                throw new InvalidOperationException("Must specify Anonymous, Username, CertificateFile, Thumbprint, or AccessToken");
            }

            Log.Debug("Access Token Lifetime Remaining: {Remaining}", connection.GetAccessTokenLifetimeRemaining());

            if (opts.Persist)
            {
                connection = Safeguard.Persist(connection);
                Log.Debug("Connection wrapped with Safeguard.Persist() for automatic token refresh");
            }

            if (opts.DelaySeconds > 0)
            {
                Log.Information("Waiting {Seconds} seconds before executing operation...", opts.DelaySeconds);
                Thread.Sleep(opts.DelaySeconds * 1000);
                Log.Information("Delay complete, proceeding with operation");
            }

            if (opts.RefreshToken)
            {
                connection.RefreshAccessToken();
                Log.Debug("Token refreshed. Lifetime Remaining: {Remaining}", connection.GetAccessTokenLifetimeRemaining());
            }

            if (opts.TokenLifetime)
            {
                var envelope = new TokenLifetimeEnvelope
                {
                    TokenLifetimeRemaining = connection.GetAccessTokenLifetimeRemaining(),
                };
                Console.WriteLine(JsonSerializer.Serialize(envelope, ToolJsonContext.Default.TokenLifetimeEnvelope));
                connection.LogOut();
                return;
            }

            if (opts.Logout)
            {
                var accessToken = connection.GetAccessToken().ToInsecureString();
                connection.LogOut();
                var envelope = new LogoutEnvelope
                {
                    AccessToken = accessToken,
                    LoggedOut = true,
                };
                Console.WriteLine(JsonSerializer.Serialize(envelope, ToolJsonContext.Default.LogoutEnvelope));
                return;
            }

            if (opts.GetToken)
            {
                var accessToken = connection.GetAccessToken().ToInsecureString();
                var envelope = new TokenEnvelope
                {
                    AccessToken = accessToken,
                };
                Console.WriteLine(JsonSerializer.Serialize(envelope, ToolJsonContext.Default.TokenEnvelope));
                return;
            }

            var additionalHeaders = ParseKeyValuePairs(opts.Headers);
            var queryParameters = ParseKeyValuePairs(opts.Parameters);

            string responseBody;
            if (!string.IsNullOrEmpty(opts.File))
            {
                responseBody = HandleStreamingRequest(opts, connection);
            }
            else if (opts.Full)
            {
                var fullResponse = connection.InvokeMethodFull(
                    opts.Service,
                    opts.Method,
                    opts.RelativeUrl,
                    opts.Body,
                    queryParameters,
                    additionalHeaders);
                var envelope = new FullResponseEnvelope
                {
                    StatusCode = (int)fullResponse.StatusCode,
                    Headers = fullResponse.Headers,
                    Body = fullResponse.Body,
                };
                responseBody = JsonSerializer.Serialize(envelope, ToolJsonContext.Default.FullResponseEnvelope);
            }
            else if (opts.Csv)
            {
                responseBody = connection.InvokeMethodCsv(
                    opts.Service,
                    opts.Method,
                    opts.RelativeUrl,
                    opts.Body,
                    queryParameters,
                    additionalHeaders);
            }
            else
            {
                responseBody = connection.InvokeMethod(
                    opts.Service,
                    opts.Method,
                    opts.RelativeUrl,
                    opts.Body,
                    queryParameters,
                    additionalHeaders);
            }

            // Log.Information(responseBody); // if JSON is nested too deep Serilog swallows a '}' -- need to file issue with them
            Console.WriteLine(responseBody);

            // Don't logout when using access token auth — the caller owns the token lifecycle
            if (string.IsNullOrEmpty(opts.AccessToken))
            {
                connection.LogOut();
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

    private static SafeguardTlsVersion? ParseTlsVersion(string value, string optionName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        switch (value.Trim())
        {
            case "1.2":
            case "12":
            case "Tls12":
            case "tls12":
            case "TLS12":
                return SafeguardTlsVersion.Tls12;
            case "1.3":
            case "13":
            case "Tls13":
            case "tls13":
            case "TLS13":
                return SafeguardTlsVersion.Tls13;
            default:
                throw new ArgumentException($"Invalid {optionName} value '{value}' (expected 1.2 or 1.3)");
        }
    }

    private static IDictionary<string, string> ParseKeyValuePairs(IEnumerable<string> pairs)
    {
        if (pairs == null || !pairs.Any())
        {
            return new Dictionary<string, string>();
        }

        var dict = new Dictionary<string, string>();
        foreach (var pair in pairs)
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex > 0)
            {
                dict[pair[..eqIndex]] = pair[(eqIndex + 1)..];
            }
        }

        return dict;
    }

    private static string HandleStreamingRequest(ToolOptions opts, ISafeguardConnection connection)
    {
        if (opts.Method == Method.Post)
        {
            using FileStream fs = File.OpenRead(opts.File);
            var progress = opts.Verbose ? new Progress<TransferProgress>(p =>
            {
                Console.Write("\rUploading: {0,3}% ({1}/{2})                                  ", p.PercentComplete, p.BytesTransferred, p.BytesTotal);
            }) : null;
            return connection.Streaming.UploadAsync(opts.Service, opts.RelativeUrl, fs, progress, cancellationToken: Cts.Token).Result;
        }
        else if (opts.Method == Method.Get)
        {
            if (File.Exists(opts.File))
            {
                throw new InvalidOperationException($"File exists, remove it first: {opts.File}");
            }

            var progress = opts.Verbose ? new Progress<TransferProgress>(p =>
            {
                if (p.BytesTotal == 0)
                {
                    Console.Write("\rDownloading: {0}", p.BytesTransferred);
                }
                else
                {
                    Console.Write("\rDownloading: {0,3}% ({1}/{2})                                  ", p.PercentComplete, p.BytesTransferred, p.BytesTotal);
                }
            }) : null;

            using (var streamResult = connection.Streaming.DownloadStreamAsync(opts.Service, opts.RelativeUrl, progress: progress, cancellationToken: Cts.Token).Result)
            {
                using var fs = new FileStream(opts.File, FileMode.Create, FileAccess.ReadWrite);
                var downloadStream = streamResult.GetStream().Result;
                downloadStream.CopyToAsync(fs, 81920).Wait();
            }

            return $"Download written to {opts.File}";
        }
        else
        {
            throw new InvalidOperationException($"Streaming is not supported for HTTP method: {opts.Method}");
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
        Console.CancelKeyPress += (sender, e) =>
        {
            Cts.Cancel();
        };

        Parser.Default.ParseArguments<ToolOptions>(args)
            .WithParsed(Execute)
            .WithNotParsed(HandleParseError);
    }
}
