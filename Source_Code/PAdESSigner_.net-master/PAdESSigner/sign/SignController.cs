using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace sign
{
    class SignController
    {

        /***
         * Sign PDF document using signDetached
         * 
         * @param src The source (input) file
         * @param dest The destination (output) file
         * @param chain The Certificate chain
         * @param pk The private key
         * @param digestAlgorithm The hash digest algorithm
         * @param subfilter The CryptoStandard
         * @param signatureAppearance The appearance of signature
         * @param crlList The certificate revocation list
         * @param ocspClient The Online Certificate Status Protocol
         * @param tsaClient The TimeStamp authority instance and connection detail
         * @param estimatedSize The reserved size for the signature
         * @throws Exception
         */
        public void Sign(string src, string dest, Org.BouncyCastle.X509.X509Certificate[] chain, ICipherParameters pk,
                DigestAlgorithm digestAlgorithm, CryptoStandard subfilter,
                SignatureAppearance signatureAppearance, ICollection<ICrlClient> crlList,
                IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
        {
            string digestAlgorithmString = GetDigestAlgorithm(digestAlgorithm);
            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithmString);
            DoSign(src, dest, chain, pks, subfilter, signatureAppearance, crlList, ocspClient, tsaClient, estimatedSize);
        }

        /***
         * Sign PDF document using signDetached
         * 
         * @param src The source (input) file
         * @param dest The destination (output) file
         * @param chain The Certificate chain
         * @param certificateInstance The instance of X509Certificate2
         * @param digestAlgorithm The hash digest algorithm
         * @param subfilter The CryptoStandard
         * @param signatureAppearance The appearance of signature
         * @param crlList The certificate revocation list
         * @param ocspClient The Online Certificate Status Protocol
         * @param tsaClient The TimeStamp authority instance and connection detail
         * @param estimatedSize The reserved size for the signature
         * @throws Exception
         */
        public void Sign(string src, string dest, Org.BouncyCastle.X509.X509Certificate[] chain, X509Certificate2 certificateInstance,
                DigestAlgorithm digestAlgorithm, CryptoStandard subfilter,
                SignatureAppearance signatureAppearance, ICollection<ICrlClient> crlList,
                IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
        {
            string digestAlgorithmString = GetDigestAlgorithm(digestAlgorithm);
            IExternalSignature pks = new X509Certificate2Signature(certificateInstance, digestAlgorithmString);
            DoSign(src, dest, chain, pks, subfilter, signatureAppearance, crlList, ocspClient, tsaClient, estimatedSize);
        }

        /***
         * Sign PDF document using signDetached
         * 
         * @param src The source (input) file
         * @param dest The destination (output) file
         * @param chain The Certificate chain
         * @param pks The IExternalSignature
         * @param subfilter The CryptoStandard
         * @param signatureAppearance The appearance of signature
         * @param crlList The certificate revocation list
         * @param ocspClient The Online Certificate Status Protocol
         * @param tsaClient The TimeStamp authority instance and connection detail
         * @param estimatedSize The reserved size for the signature
         * @throws Exception
         */
        private void DoSign(string src, string dest, Org.BouncyCastle.X509.X509Certificate[] chain, IExternalSignature pks, CryptoStandard subfilter,
                SignatureAppearance signatureAppearance, ICollection<ICrlClient> crlList,
                IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
        {
            PdfReader reader = new PdfReader(src);
            FileStream fileOutputStream = new FileStream(dest, FileMode.Create);
            PdfStamper stamper = PdfStamper.CreateSignature(reader, fileOutputStream, '\0', null, true);

            // Create the signature appearance
            Rectangle rect = new Rectangle(signatureAppearance.X, signatureAppearance.Y, signatureAppearance.Width, signatureAppearance.Height);

            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            appearance.Reason = signatureAppearance.Reason;
            appearance.Location = signatureAppearance.Location;
            appearance.ReuseAppearance = false;

            appearance.SetVisibleSignature(rect, signatureAppearance.PageNumber, signatureAppearance.SignatureFieldName);

            Image image = null;
            if (signatureAppearance.SignatureImage != null)
            {
                image = Image.GetInstance(signatureAppearance.SignatureImage);
                appearance.SignatureGraphic = image;
            }

            if (signatureAppearance.SignatureVisibility == SignatureVisibility.VISIBLE)
            {
                switch (signatureAppearance.SignaturePattern)
                {
                    case SignaturePattern.DESCRIPTION:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                        break;
                    case SignaturePattern.NAME_AND_DESCRIPTION:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION;
                        break;
                    case SignaturePattern.GRAPHIC_AND_DESCRIPTION:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION;
                        appearance.SignatureGraphic = image;
                        break;
                    case SignaturePattern.GRAPHIC:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                        appearance.SignatureGraphic = image;
                        break;
                    default:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                        break;
                }
            }

            switch (signatureAppearance.SignatureLevel)
            {
                case SignatureLevel.APPROVAL:
                    appearance.CertificationLevel = 0;
                    break;
                case SignatureLevel.CERTIFIED_NO_CHANGES_ALLOW:
                    appearance.CertificationLevel = 1;
                    break;
                case SignatureLevel.CERTIFIED_FORM_FILLING:
                    appearance.CertificationLevel = 2;
                    break;
                case SignatureLevel.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS:
                    appearance.CertificationLevel = 3;
                    break;
                default:
                    appearance.CertificationLevel = 0;
                    break;
            }

            MakeSignature.SignDetached(appearance, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
            stamper.Close();
        }

        /**
         * Get digest type in string from input Enum
         * @param digestAlgorithm The digest algorithm
         * @return string
         */
        public string GetDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            switch (digestAlgorithm)
            {
                case DigestAlgorithm.SHA256:
                    return "SHA256";
                case DigestAlgorithm.SHA384:
                    return "SHA384";
                case DigestAlgorithm.SHA512:
                    return "SHA512";
                default:
                    throw new Exception("Unrecognized/Unsupported algorithm");
            }
        }
    }
}
