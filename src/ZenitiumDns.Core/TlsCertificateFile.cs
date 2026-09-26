using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ZenitiumDns.Core
{
    static class TlsCertificateFile
    {
        public static bool IsPkcs12(string certificatePath)
        {
            switch (Path.GetExtension(certificatePath).ToLowerInvariant())
            {
                case ".pfx":
                case ".p12":
                    return true;

                default:
                    return false;
            }
        }

        public static SslStreamCertificateContext Load(string certificatePath, string privateKeyPath, string password, out X509Certificate2 serverCertificate)
        {
            if (!File.Exists(certificatePath))
                throw new ArgumentException("TLS certificate file does not exists: " + certificatePath);

            X509Certificate2Collection additionalCertificates = new X509Certificate2Collection();
            serverCertificate = null;

            if (IsPkcs12(certificatePath))
            {
                X509Certificate2Collection certificateCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(certificatePath, password, X509KeyStorageFlags.PersistKeySet);

                foreach (X509Certificate2 certificate in certificateCollection)
                {
                    if ((serverCertificate is null) && certificate.HasPrivateKey)
                        serverCertificate = certificate;
                    else
                        additionalCertificates.Add(certificate);
                }

                if (serverCertificate is null)
                    throw new ArgumentException("TLS certificate file must contain a certificate with private key: " + certificatePath);
            }
            else
            {
                string keyPath = string.IsNullOrEmpty(privateKeyPath) ? certificatePath : privateKeyPath;

                if (!File.Exists(keyPath))
                    throw new ArgumentException("TLS private key file does not exists: " + keyPath);

                if (File.ReadAllText(keyPath).Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal))
                    throw new ArgumentException("Encrypted private keys must use the PKCS#8 format (BEGIN ENCRYPTED PRIVATE KEY). Convert with: openssl pkcs8 -topk8 -v2 aes256 -in key.pem -out key-pkcs8.pem");

                using (X509Certificate2 pemCertificate = string.IsNullOrEmpty(password) ? X509Certificate2.CreateFromPemFile(certificatePath, keyPath) : X509Certificate2.CreateFromEncryptedPemFile(certificatePath, password, keyPath))
                {
                    serverCertificate = X509CertificateLoader.LoadPkcs12(pemCertificate.Export(X509ContentType.Pkcs12), null);
                }

                X509Certificate2Collection chain = new X509Certificate2Collection();
                chain.ImportFromPemFile(certificatePath);

                foreach (X509Certificate2 certificate in chain)
                {
                    if (!certificate.Thumbprint.Equals(serverCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
                        additionalCertificates.Add(certificate);
                }
            }

            return SslStreamCertificateContext.Create(serverCertificate, additionalCertificates, false);
        }

        public static DateTime GetLastWriteTimeUtc(string certificatePath, string privateKeyPath)
        {
            DateTime lastWriteTime = GetFileLastWriteTimeUtc(certificatePath);

            if (!string.IsNullOrEmpty(privateKeyPath))
            {
                DateTime keyLastWriteTime = GetFileLastWriteTimeUtc(privateKeyPath);
                if (keyLastWriteTime > lastWriteTime)
                    lastWriteTime = keyLastWriteTime;
            }

            return lastWriteTime;
        }

        private static DateTime GetFileLastWriteTimeUtc(string path)
        {
            FileInfo fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
                return DateTime.MinValue;

            DateTime lastWriteTime = fileInfo.LastWriteTimeUtc;

            if (fileInfo.LinkTarget is not null)
            {
                FileSystemInfo target = fileInfo.ResolveLinkTarget(true);
                if ((target is not null) && target.Exists && (target.LastWriteTimeUtc > lastWriteTime))
                    lastWriteTime = target.LastWriteTimeUtc;
            }

            return lastWriteTime;
        }
    }
}
