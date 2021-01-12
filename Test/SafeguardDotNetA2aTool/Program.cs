﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.A2A;
using Serilog;

namespace SafeguardDotNetA2aTool
{
    internal class Program
    {
        private static SecureString PromptForSecret(string name)
        {
            Console.Write($"{name}: ");
            var password = new SecureString();
            while (true)
            {
                var keyInput = Console.ReadKey(true);
                if (keyInput.Key == ConsoleKey.Enter)
                    break;
                if (keyInput.Key == ConsoleKey.Backspace)
                {
                    if (password.Length <= 0)
                        continue;
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

        private static ISafeguardA2AContext CreateA2AContext(ToolOptions opts)
        {
            ISafeguardA2AContext context;
            if (!string.IsNullOrEmpty(opts.CertificateFile))
            {
                var password = HandlePassword(opts.ReadPassword);
                if (opts.CertificateAsData)
                {
                    var bytes = File.ReadAllBytes(opts.CertificateFile);
                    context = Safeguard.A2A.GetContext(opts.Appliance, bytes, password, opts.ApiVersion, opts.Insecure);
                }
                else
                {
                    context = Safeguard.A2A.GetContext(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion,
                        opts.Insecure);
                }
            }
            else if (!string.IsNullOrEmpty(opts.Thumbprint))
            {
                context = Safeguard.A2A.GetContext(opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
            }
            else
            {
                throw new Exception("Must specify CertificateFile or Thumbprint");
            }
            return context;
        }

        private static void Execute(ToolOptions opts)
        {
            try
            {
                var config = new LoggerConfiguration();
                config.WriteTo.ColoredConsole(outputTemplate: "{Message:lj}{NewLine}{Exception}");

                if (opts.Verbose)
                    config.MinimumLevel.Debug();
                else
                    config.MinimumLevel.Information();

                Log.Logger = config.CreateLogger();

                using (var context = CreateA2AContext(opts))
                {
                    if (opts.ApiKey.Equals("?"))
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
                            Log.Information(ObjectDumper.Dump(accounts));
                        }
                        if (opts.PrivateKey)
                        {
                            using (var responseBody = context.RetrievePrivateKey(opts.ApiKey.ToSecureString(), opts.KeyFormat))
                                Log.Information(responseBody.ToInsecureString());
                        }
                        else
                        {
                            using (var responseBody = context.RetrievePassword(opts.ApiKey.ToSecureString()))
                                Log.Information(responseBody.ToInsecureString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Fatal exception occurred");
                Environment.Exit(1);
            }
        }


        private static void HandleParseError(IEnumerable<Error> errors)
        {
            Log.Logger = new LoggerConfiguration().WriteTo.ColoredConsole().CreateLogger();
            Log.Error("Invalid command line options");
            Environment.Exit(1);
        }


        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<ToolOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
