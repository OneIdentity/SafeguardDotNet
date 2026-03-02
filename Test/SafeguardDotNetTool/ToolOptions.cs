// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetTool;

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
        'A',
        "Anonymous",
        Required = true,
        SetName = "AnonymousSet",
        HelpText = "Do not authenticate, call API anonymously")]
    public bool Anonymous { get; set; }

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
        'i',
        "IdentityProvider",
        Required = false,
        Default = null,
        SetName = "PasswordSet",
        HelpText = "Safeguard identity provider to use for rSTS")]
    public string IdentityProvider { get; set; }

    [Option(
        'u',
        "Username",
        Required = true,
        SetName = "PasswordSet",
        HelpText = "Safeguard username to use to authenticate")]
    public string Username { get; set; }

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
        's',
        "Service",
        Required = true,
        HelpText = "Safeguard service to use")]
    public Service Service { get; set; }

    [Option(
        'm',
        "Method",
        Required = true,
        HelpText = "HTTP Method to use")]
    public Method Method { get; set; }

    [Option(
        'U',
        "RelativeUrl",
        Required = true,
        HelpText = "HTTP Method to use")]
    public string RelativeUrl { get; set; }

    [Option(
        'b',
        "Body",
        Required = false,
        Default = null,
        HelpText = "JSON body as string")]
    public string Body { get; set; }

    [Option(
        'C',
        "Csv",
        Required = false,
        Default = null,
        HelpText = "Request for a response as CSV")]
    public bool Csv { get; set; }

    [Option(
        'F',
        "File",
        Required = false,
        Default = null,
        HelpText = "Path to a file to stream as the request body")]
    public string File { get; set; }
}
