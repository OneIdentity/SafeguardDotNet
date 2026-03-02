// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;

    internal static class CertificateUtilities
    {
        public static X509Certificate2 GetClientCertificateFromStore(string thumbprint)
        {
            try
            {
                X509Certificate2 cert;
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadOnly);
                    cert = store.Certificates.OfType<X509Certificate2>()
                        .FirstOrDefault(x => string.Equals(x.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
                }

                if (cert == null)
                {
                    using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        cert = store.Certificates.OfType<X509Certificate2>()
                            .FirstOrDefault(x => string.Equals(x.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
                        if (cert == null)
                        {
                            throw new SafeguardDotNetException("Unable to find certificate matching " +
                                                               $"thumbprint={thumbprint} in Computer or User store");
                        }
                    }
                }

                return cert;
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from thumbprint={thumbprint}", ex);
            }
        }

        public static X509Certificate2 GetClientCertificateFromFile(string filepath, SecureString password)
        {
            try
            {
                return new X509Certificate2(filepath, password);
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from file={filepath}", ex);
            }
        }

        public static X509Certificate2 GetClientCertificateFromDataBuffer(byte[] data, SecureString password)
        {
            try
            {
                return password == null ? new X509Certificate2(data) : new X509Certificate2(data, password);
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from data buffer={data.Length} bytes", ex);
            }
        }
    }
}
