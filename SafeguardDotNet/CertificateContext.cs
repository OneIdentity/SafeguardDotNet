using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace OneIdentity.SafeguardDotNet
{
    internal class CertificateContext : IDisposable
    {
        public CertificateContext(string thumbprint)
        {
            Thumbprint = thumbprint;
            Certificate = CertificateUtilities.GetClientCertificateFromStore(Thumbprint);
        }

        public CertificateContext(string filepath, SecureString password)
        {
            FilePath = filepath;
            Password = password;
            Certificate = CertificateUtilities.GetClientCertificateFromFile(FilePath, Password);
        }

        private CertificateContext()
        {}
        private string Thumbprint { get; set; }
        private string FilePath { get; set; }
        private SecureString Password { get; set; }

        public X509Certificate2 Certificate { get; private set; }

        public CertificateContext Clone()
        {
            var clone = new CertificateContext
            {
                Thumbprint = Thumbprint,
                FilePath = FilePath,
                Password = Password?.Copy()
            };
            clone.Certificate = clone.Thumbprint != null
                ? CertificateUtilities.GetClientCertificateFromStore(Thumbprint)
                : CertificateUtilities.GetClientCertificateFromFile(FilePath, Password);
            return clone;
        }

        public override string ToString()
        {
            return $"{(string.IsNullOrEmpty(FilePath) ? $"thumbprint={Thumbprint}" : $"file={FilePath}")}";
        }

        public void Dispose()
        {
            Password?.Dispose();
            Certificate?.Dispose();
        }
    }
}
