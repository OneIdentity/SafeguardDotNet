using System;
using System.Collections.Generic;
using System.Net;
using System.Security;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using Serilog;

namespace SafeguardDotNetExceptionTest
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

        private static void TestConnectExceptions(string appliance)
        {
            Console.WriteLine("Test connect anonymous with bad host");
            try
            {
                using var connection = Safeguard.Connect("bad.dns.name", ignoreSsl: true);
                throw new Exception("Bad host anonymous did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (!string.Equals(ex.Message,
                    "Unable to anonymously connect to bad.dns.name, Error: No such host is known. No such host is known.")
                )
                    throw;
                if (ex.HttpStatusCode != null)
                    throw;
                if (ex.HasResponse)
                    throw;
                if (ex.ErrorCode != null)
                    throw;
                if (ex.ErrorMessage != null)
                    throw;
            }

            Console.WriteLine("Test connect with bad host");
            try
            {
                using var connection = Safeguard.Connect("bad.dns.name", "local", "admin", "a".ToSecureString(), ignoreSsl: true);
                throw new Exception("Bad host did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (!string.Equals(ex.Message,
                    "Unable to connect to RSTS to find identity provider scopes, Error: No such host is known. No such host is known.")
                )
                    throw;
                if (ex.HttpStatusCode != null)
                    throw;
                if (ex.HasResponse)
                    throw;
                if (ex.ErrorCode != null)
                    throw;
                if (ex.ErrorMessage != null)
                    throw;
            }

            Console.WriteLine("Test connect with unknown user");
            try
            {
                using var connection = Safeguard.Connect(appliance, "local", "thisisnevergonnabethere", "a".ToSecureString(), ignoreSsl:true);
                throw new Exception("Unknown user did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
                    throw;
                if (!ex.HasResponse)
                    throw;
                if (ex.ErrorCode != null)
                    throw;
                if (ex.ErrorMessage != null)
                    throw;
            }

            Console.WriteLine("Test connect with bad password");
            try
            {
                using var connection = Safeguard.Connect(appliance, "local", "admin", "a".ToSecureString(), ignoreSsl: true);
                throw new Exception("Bad password did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
                    throw;
                if (!ex.HasResponse)
                    throw;
                if (ex.ErrorCode != null)
                    throw;
                if (ex.ErrorMessage != null)
                    throw;
            }
        }

        private static void TestApiExceptions(ISafeguardConnection connection)
        {
            Console.WriteLine("Test exception with no response body");
            try
            {
                connection.InvokeMethod(Service.Core, Method.Get, "This/Does/nt/Exist");
                throw new Exception("Nonexistent URL did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (ex.HttpStatusCode != HttpStatusCode.NotFound)
                    throw;
                if (!ex.HasResponse)
                    throw;
                if (ex.ErrorCode != null)
                    throw;
                if (ex.ErrorMessage != null)
                    throw;
            }

            Console.WriteLine("Test exception for bad request no filter");
            try
            {
                connection.InvokeMethod(Service.Core, Method.Get, "Me/RequestableAssets", 
                    parameters: new Dictionary<string, string>(){["filter"] = "This eq 'broken'"});
                throw new Exception("Bad filter did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
                    throw;
                if (!ex.HasResponse)
                    throw;
                if (ex.ErrorCode != 70009)
                    throw;
                if (!string.Equals(ex.ErrorMessage,
                    "Invalid filter property - 'This' is not a valid filter property name."))
                    throw;
            }

            Console.WriteLine("Test exception with model state issues");
            try
            {
                connection.InvokeMethod(Service.Appliance, Method.Put, "NetworkInterfaces/X1",
                    "{\"Name\":\"X1\",\"LinkDuplex\":\"FakeValue\"}");
                throw new Exception("Bad model state did not throw an exception");
            }
            catch (SafeguardDotNetException ex)
            {
                Console.WriteLine(ex);
                if (ex.HttpStatusCode != HttpStatusCode.BadRequest)
                    throw;
                if (!ex.HasResponse)
                    throw;
                if (ex.ErrorCode != 70000)
                    throw;
                if (!string.Equals(ex.ErrorMessage, "The request is invalid."))
                    throw;
            }
        }

        private static void Execute(TestOptions opts)
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

                TestConnectExceptions(opts.Appliance);

                ISafeguardConnection connection;
                if (!string.IsNullOrEmpty(opts.Username))
                {
                    var password = HandlePassword(opts.ReadPassword);
                    connection = Safeguard.Connect(opts.Appliance, opts.IdentityProvider, opts.Username, password,
                        opts.ApiVersion, opts.Insecure);
                }
                else if (opts.Anonymous)
                {
                    connection = Safeguard.Connect(opts.Appliance, opts.ApiVersion, opts.Insecure);
                }
                else
                {
                    throw new Exception("Must specify Anonymous or Username");
                }

                Log.Debug($"Access Token Lifetime Remaining: {connection.GetAccessTokenLifetimeRemaining()}");

                TestApiExceptions(connection);

                connection.LogOut();
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
            Parser.Default.ParseArguments<TestOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
