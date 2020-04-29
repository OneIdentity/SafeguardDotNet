using CommandLine;

namespace SafeguardDotNetExceptionTest
{
    internal class TestOptions
    {
        [Option('a', "Appliance", Required = true,
            HelpText = "IP address or hostname of Safeguard appliance")]
        public string Appliance { get; set; }

        [Option('x', "Insecure", Required = false, Default = false,
            HelpText = "Ignore validation of Safeguard appliance SSL certificate")]
        public bool Insecure { get; set; }

        [Option('p', "ReadPassword", Required = false, Default = false,
            HelpText = "Read any required password from console stdin")]
        public bool ReadPassword { get; set; }

        [Option('A', "Anonymous", Required = true, SetName = "AnonymousSet",
            HelpText = "Do not authenticate, call API anonymously")]
        public bool Anonymous { get; set; }

        [Option('V', "Verbose", Required = false, Default = false,
            HelpText = "Display verbose debug output")]
        public bool Verbose { get; set; }

        [Option('v', "ApiVersion", Required = false, Default = 2,
            HelpText = "Version of the Safeguard API to use")]
        public int ApiVersion { get; set; }

        [Option('i', "IdentityProvider", Required = false, Default = null, SetName = "PasswordSet",
            HelpText = "Safeguard identity provider to use for rSTS")]
        public string IdentityProvider { get; set; }

        [Option('u', "Username", Required = true, SetName = "PasswordSet",
            HelpText = "Safeguard username to use to authenticate")]
        public string Username { get; set; }
    }
}
