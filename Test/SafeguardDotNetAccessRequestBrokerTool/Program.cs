using System;
using System.Collections.Generic;
using System.Security;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.A2A;
using Serilog;

namespace SafeguardDotNetAccessRequestBrokerTool
{
    internal static class StringEnhancements
    {
        public static bool IsNumeric(this string str)
        {
            return int.TryParse(str, out _);
        }
    }

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
                context = Safeguard.A2A.GetContext(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion,
                    opts.Insecure);
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

        private static BrokeredAccessRequest GetBrokeredAccessRequestObject(ToolOptions opts)
        {
            var accessRequest = new BrokeredAccessRequest
            {
                AccessType = opts.AccessType,
                TicketNumber = opts.TicketNumber,
                ReasonComment = opts.ReasonComment,
                RequestedFor = opts.RequestedFor?.ToUniversalTime()
            };
            if (opts.ForUser.IsNumeric())
                accessRequest.ForUserId = int.Parse(opts.ForUser);
            else
                accessRequest.ForUserName = opts.ForUser;
            if (opts.Asset.IsNumeric())
                accessRequest.AssetId = int.Parse(opts.Asset);
            else
                accessRequest.AssetName = opts.Asset;
            if (!string.IsNullOrEmpty(opts.Account))
            {
                if (opts.Account.IsNumeric())
                    accessRequest.AccountId = int.Parse(opts.Account);
                else
                    accessRequest.AccountName = opts.Account;
            }
            if (!string.IsNullOrEmpty(opts.AccountAsset))
            {
                if (opts.AccountAsset.IsNumeric())
                    accessRequest.AccountAssetId = int.Parse(opts.AccountAsset);
                else
                    accessRequest.AccountAssetName = opts.AccountAsset;
            }
            if (!string.IsNullOrEmpty(opts.ReasonCode))
            {
                if (opts.ReasonCode.IsNumeric())
                    accessRequest.ReasonCodeId = int.Parse(opts.ReasonCode);
                else
                    accessRequest.ReasonCode = opts.ReasonCode;
            }
            if (!string.IsNullOrEmpty(opts.RequestedDuration))
                accessRequest.RequestedDuration = TimeSpan.Parse(opts.RequestedDuration);
            return accessRequest;
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
                    var responseBody =
                        context.BrokerAccessRequest(opts.ApiKey.ToSecureString(), GetBrokeredAccessRequestObject(opts));
                    Log.Information(responseBody);
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
