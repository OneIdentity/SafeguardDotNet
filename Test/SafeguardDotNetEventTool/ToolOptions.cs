using CommandLine;

namespace SafeguardDotNetEventTool
{
    internal class ToolOptions
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

        [Option('t', "Thumbprint", Required = true, SetName = "CertificateThumbprint",
            HelpText = "Thumbprint for client certificate in user certificate store")]
        public string Thumbprint { get; set; }

        [Option('c', "CertificateFile", Required = true, SetName = "CertificateFile",
            HelpText = "File path for client certificate")]
        public string CertificateFile { get; set; }

        [Option('A', "ApiKey", Required = false, Default = null,
            HelpText = "ApiKey for listening to Safeguard A2A")]
        public string ApiKey { get; set; }

        [Option('E', "Event", Required = false,
            HelpText = "Safeguard event to listen for")]
        public string Event { get; set; }

        [Option('P', "Persistent", Required = false,
            HelpText = "Use persistent listeners")]
        public bool Persistent { get; set; }
    }
}
