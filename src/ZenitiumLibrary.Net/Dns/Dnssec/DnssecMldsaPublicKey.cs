using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Security.Cryptography;

namespace ZenitiumLibrary.Net.Dns.Dnssec
{
    public class DnssecMldsaPublicKey : DnssecPublicKey
    {
        #region variables

        public const int MLDSA44_PUBLIC_KEY_SIZE = 1312;
        public const int MLDSA44_SIGNATURE_SIZE = 2420;

        readonly MLDsaPublicKeyParameters _mldsaPublicKey;

        #endregion

        #region constructor

        public DnssecMldsaPublicKey(byte[] rawPublicKey)
            : base(rawPublicKey)
        {
            if (rawPublicKey.Length != MLDSA44_PUBLIC_KEY_SIZE)
                return;

            try
            {
                _mldsaPublicKey = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_44, rawPublicKey);
            }
            catch (ArgumentException)
            { }
        }

        #endregion

        #region public

        public override bool IsSignatureValid(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            if ((_mldsaPublicKey is null) || (signature.Length != MLDSA44_SIGNATURE_SIZE))
                return false;

            MLDsaSigner signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            signer.Init(false, _mldsaPublicKey);
            signer.BlockUpdate(hash, 0, hash.Length);

            return signer.VerifySignature(signature);
        }

        #endregion

        #region properties

        public override bool IsAlgorithmSupported
        { get { return true; } }

        #endregion
    }
}
