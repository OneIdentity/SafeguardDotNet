// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetA2aTool;

using CommandLine;

using OneIdentity.SafeguardDotNet;

internal class ToolOptions
{
    [Option(
        'a',
        "Appliance",
        Required = true,
        HelpText = "IP address or hostname of Safeguard appliance")]
    public string Appliance { get; set; }

    [Option(
        'x',
        "Insecure",
        Required = false,
        Default = false,
        HelpText = "Ignore validation of Safeguard appliance SSL certificate")]
    public bool Insecure { get; set; }

    [Option(
        'p',
        "ReadPassword",
        Required = false,
        Default = false,
        HelpText = "Read any required password from console stdin")]
    public bool ReadPassword { get; set; }

    [Option(
        'V',
        "Verbose",
        Required = false,
        Default = false,
        HelpText = "Display verbose debug output")]
    public bool Verbose { get; set; }

    [Option(
        'v',
        "ApiVersion",
        Required = false,
        Default = 4,
        HelpText = "Version of the Safeguard API to use")]
    public int ApiVersion { get; set; }

    [Option(
        't',
        "Thumbprint",
        Required = true,
        SetName = "CertificateThumbprint",
        HelpText = "Thumbprint for client certificate in user certificate store")]
    public string Thumbprint { get; set; }

    [Option(
        'c',
        "CertificateFile",
        Required = true,
        SetName = "CertificateFile",
        HelpText = "File path for client certificate")]
    public string CertificateFile { get; set; }

    [Option(
        'd',
        "CertificateAsData",
        Required = false,
        SetName = "CertificateFile",
        HelpText = "Create client certificate as data buffer")]
    public bool CertificateAsData { get; set; }

    [Option(
        'A',
        "ApiKey",
        Required = true,
        Default = null,
        HelpText = "ApiKey for call Safeguard A2A")]
    public string ApiKey { get; set; }

    [Option(
        'K',
        "PrivateKey",
        Required = false,
        Default = false,
        HelpText = "Retrieves or sets the SSH private key rather than password (see -PrivateKeyFile)")]
    public bool PrivateKey { get; set; }

    [Option(
        'P',
        "ApiKeySecret",
        Required = false,
        Default = false,
        HelpText = "Request API key secret rather than password")]
    public bool ApiKeySecret { get; set; }

    [Option(
        'M',
        "PrivateKeyFile",
        Required = false,
        Default = null,
        HelpText = "If specified, sets the SSH private key")]
    public string PrivateKeyFile { get; set; }

    [Option(
        'N',
        "NewPassword",
        Required = false,
        Default = false,
        HelpText = "If specified, sets the password")]
    public bool NewPassword { get; set; }

    [Option(
        'R',
        "RetrievableAccounts",
        Required = false,
        Default = false,
        HelpText = "Display retrievable account information")]
    public bool RetrievableAccounts { get; set; }

    [Option(
        'F',
        "KeyFormat",
        Required = false,
        Default = null,
        HelpText = "Private key format to request")]
    public KeyFormat KeyFormat { get; set; }
}
