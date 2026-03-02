// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetAccessRequestBrokerTool;

using System;

using CommandLine;

using OneIdentity.SafeguardDotNet.A2A;

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
        'U',
        "ForUser",
        Required = true,
        Default = null,
        HelpText = "")]
    public string ForUser { get; set; }

    [Option(
        'Y',
        "AccessType",
        Required = true,
        Default = null,
        HelpText = "Type of access to request")]
    public BrokeredAccessRequestType AccessType { get; set; }

    [Option(
        'S',
        "Asset",
        Required = true,
        Default = null,
        HelpText = "ID or name of Asset to request")]
    public string Asset { get; set; }

    [Option(
        'C',
        "Account",
        Default = null,
        HelpText = "ID or name of Account to request")]
    public string Account { get; set; }

    [Option(
        'D',
        "AccountAsset",
        Default = null,
        HelpText = "ID or name of Asset the Account belongs to for request")]
    public string AccountAsset { get; set; }

    [Option(
        'T',
        "TicketNumber",
        Default = null,
        HelpText = "Ticket number to include in the request")]
    public string TicketNumber { get; set; }

    [Option(
        'R',
        "ReasonCode",
        Default = null,
        HelpText = "ID or name of reason code to include in request")]
    public string ReasonCode { get; set; }

    [Option(
        'M',
        "ReasonComment",
        Default = null,
        HelpText = "Comment to include in the request")]
    public string ReasonComment { get; set; }

    [Option(
        'F',
        "RequestedFor",
        Default = null,
        HelpText = "Date/time of the request")]
    public DateTime? RequestedFor { get; set; }

    [Option(
        'Z',
        "RequestedDuration",
        Default = null,
        HelpText = "Duration of the request (format=dd.hh:mm:ss)")]
    public string RequestedDuration { get; set; }
}
