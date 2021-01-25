using CommandLine;
using OneIdentity.SafeguardDotNet;

namespace SafeguardDotNetA2aTool
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

        [Option('t', "Thumbprint", Required = true, SetName = "CertificateThumbprint",
            HelpText = "Thumbprint for client certificate in user certificate store")]
        public string Thumbprint { get; set; }

        [Option('c', "CertificateFile", Required = true, SetName = "CertificateFile",
            HelpText = "File path for client certificate")]
        public string CertificateFile { get; set; }

        [Option('d', "CertificateAsData", Required = false, SetName = "CertificateFile",
            HelpText = "Create client certificate as data buffer")]
        public bool CertificateAsData { get; set; }

        [Option('A', "ApiKey", Required = true, Default = null,
            HelpText = "ApiKey for call Safeguard A2A")]
        public string ApiKey { get; set; }

        [Option('K', "PrivateKey", Required = false, Default = false,
            HelpText = "Request private key rather than password")]
        public bool PrivateKey { get; set; }

        [Option('R', "RetrievableAccounts", Required = false, Default = false,
            HelpText = "Display retrievable account information")]
        public bool RetrievableAccounts { get; set; }

        [Option('F', "KeyFormat", Required = false, Default = null,
            HelpText = "Private key format to request")]
        public KeyFormat KeyFormat { get; set; }
    }
}
