// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;

    internal class CertificateContext : IDisposable
    {
        private enum ContextType
        {
            Thumbprint,
            File,
            Data,
        }

        public CertificateContext(string thumbprint)
        {
            Type = ContextType.Thumbprint;
            Thumbprint = thumbprint;
            Certificate = CertificateUtilities.GetClientCertificateFromStore(Thumbprint);
        }

        public CertificateContext(string filepath, SecureString password)
        {
            Type = ContextType.File;
            FilePath = filepath;
            Password = password;
            Certificate = CertificateUtilities.GetClientCertificateFromFile(FilePath, Password);
        }

        public CertificateContext(IEnumerable<byte> data, SecureString password)
        {
            Type = ContextType.Data;
            DataBuffer = data.ToArray();
            Password = password;
            Certificate = CertificateUtilities.GetClientCertificateFromDataBuffer(DataBuffer, Password);
        }

        private CertificateContext()
        {
        }

        private ContextType Type { get; set; }

        private string Thumbprint { get; set; }

        private string FilePath { get; set; }

        private byte[] DataBuffer { get; set; }

        private SecureString Password { get; set; }

        public X509Certificate2 Certificate { get; private set; }

        public CertificateContext Clone()
        {
            var clone = new CertificateContext
            {
                Type = Type,
                Thumbprint = Thumbprint,
                FilePath = FilePath,
                DataBuffer = DataBuffer?.ToArray(),
                Password = Password?.Copy(),
            };

            switch (Type)
            {
                case ContextType.Thumbprint:
                    clone.Certificate = CertificateUtilities.GetClientCertificateFromStore(Thumbprint);
                    break;
                case ContextType.File:
                    clone.Certificate = CertificateUtilities.GetClientCertificateFromFile(FilePath, Password);
                    break;
                case ContextType.Data:
                    clone.Certificate = CertificateUtilities.GetClientCertificateFromDataBuffer(DataBuffer, Password);
                    break;
                default:
                    throw new SafeguardDotNetException(
                        $"Error calling Clone() on unknown CertificateContext type: {Enum.GetName(typeof(ContextType), Type)}");
            }

            return clone;
        }

        public override string ToString()
        {
            switch (Type)
            {
                case ContextType.Thumbprint:
                    return $"thumbprint={Thumbprint}";
                case ContextType.File:
                    return $"file={FilePath}";
                case ContextType.Data:
                    return $"data={DataBuffer.Length} bytes";
                default:
#pragma warning disable S3877 // Throw in default case is intentional for exhaustive enum handling
                    throw new SafeguardDotNetException(
                        $"Error calling ToString() on unknown CertificateContext type: {Enum.GetName(typeof(ContextType), Type)}");
#pragma warning restore S3877
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                Password?.Dispose();
                Certificate?.Dispose();
            }
        }
    }
}
