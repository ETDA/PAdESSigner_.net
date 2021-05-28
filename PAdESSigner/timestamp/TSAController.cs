using System;
using System.IO;
using System.Collections;
using System.Net;
using System.Text;
using System.util;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Crypto;
using iTextSharp.text.log;
using iTextSharp.text.error_messages;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text.pdf.security;

namespace timestamp
{

    public class TSAController : ITSAClient
    {

        protected internal String tsaURL;
        protected internal String tsaUsername;
        protected internal String tsaPassword;
        protected ITSAInfoBouncyCastle tsaInfo;
        public const int DEFAULTTOKENSIZE = 4096;

        protected internal int tokenSizeEstimate;

        public const String DEFAULTHASHALGORITHM = "SHA-256";

        protected internal String digestAlgorithm;

        protected internal String tsaCertificateFile;
        protected internal String tsaCertificatePassword;
        protected internal bool tsacert;

        /*
         * @param url String - Time Stamp Authority URL (i.e. "http://rfc3161timestamp.globalsign.com/advanced")
         */
        public TSAController(String url)
            : this(url, null, null, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHM)
        {
        }

        /*
         * @param url String - Time Stamp Authority URL (i.e. "https://bteszt.e-szigno.hu/tsa")
         * @param username String - test
         * @param password String - test
         */
        public TSAController(String url, String username, String password)
            : this(url, username, password, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHM)
        {
        }

        /*
         * @param url String - Time Stamp Authority URL(i.e. "https://bteszt.e-szigno.hu/tsa")
         * @param username String - test
         * @param password String - test
         * @param tokSzEstimate int - estimated size of received time stamp token(DER encoded)
         */
        public TSAController(String url, String username, String password, int tokSzEstimate, String digestAlgorithm)
        {
            this.tsaURL = url;
            this.tsaUsername = username;
            this.tsaPassword = password;
            this.tokenSizeEstimate = tokSzEstimate;
            this.digestAlgorithm = digestAlgorithm;
        }

        /*
         * @param url String - Time Stamp Authority URL (i.e. "https://teszt.e-szigno.hu/tsa")
         * @param certificatefile String - T01/pfx/authtsa.pfx
         * @param certificatepass String - 123456
         * @param tsawithcert Bool - true
         */
        public TSAController(String url, String certificatefile, String certificatepass, bool tsawithcert)
        {
            this.tsaURL = url;
            this.tsaCertificateFile = certificatefile;
            this.tsaCertificatePassword = certificatepass;
            this.tsacert = tsawithcert;
        }

        public void SetTSAInfo(ITSAInfoBouncyCastle tsaInfo)
        {
            this.tsaInfo = tsaInfo;
        }

        public virtual int GetTokenSizeEstimate()
        {
            return tokenSizeEstimate;
        }

        public IDigest GetMessageDigest()
        {
            return DigestAlgorithms.GetMessageDigest("SHA-256");
        }

        public virtual byte[] GetTimeStampToken(byte[] imprint)
        {
            byte[] respBytes = null;
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.SetCertReq(true);
            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks + Environment.TickCount);
            TimeStampRequest request = tsqGenerator.Generate(DigestAlgorithms.GetAllowedDigests("SHA-256"), imprint, nonce);
            byte[] requestBytes = request.GetEncoded();

            respBytes = GetTSAResponse(requestBytes);

            TimeStampResponse response = new TimeStampResponse(respBytes);

            response.Validate(request);
            PkiFailureInfo failure = response.GetFailInfo();
            int value = (failure == null) ? 0 : failure.IntValue;
            if (value != 0)
            {
                throw new IOException(MessageLocalization.GetComposedMessage("invalid.tsa.1.response.code.2", tsaURL, value));
            }

            TimeStampToken tsToken = response.TimeStampToken;
            if (tsToken == null)
            {
                throw new IOException(MessageLocalization.GetComposedMessage("tsa.1.failed.to.return.time.stamp.token.2", tsaURL, response.GetStatusString()));
            }
            TimeStampTokenInfo tsTokenInfo = tsToken.TimeStampInfo;
            byte[] encoded = tsToken.GetEncoded();

            if (tsaInfo != null)
            {
                tsaInfo.InspectTimeStampTokenInfo(tsTokenInfo);
            }
            this.tokenSizeEstimate = encoded.Length + 32;
            return encoded;
        }


        protected internal virtual byte[] GetTSAResponse(byte[] requestBytes)
        {

            HttpWebRequest con = (HttpWebRequest)WebRequest.Create(tsaURL);
            con.ContentLength = requestBytes.Length;
            con.ContentType = "application/timestamp-query";
            con.Method = "POST";
            if ((tsaUsername != null) && !tsaUsername.Equals(""))
            {
                string authInfo = tsaUsername + ":" + tsaPassword;
                authInfo = Convert.ToBase64String(Encoding.Default.GetBytes(authInfo), Base64FormattingOptions.None);
                con.Headers["Authorization"] = "Basic " + authInfo;
            }

            if ((tsaCertificateFile != null) && !tsaCertificateFile.Equals(""))
            {
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                certificates.Import(tsaCertificateFile, tsaCertificatePassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                con.ClientCertificates = certificates;
                con.ContentLength = requestBytes.Length;
            }
            Stream outp = con.GetRequestStream();
            outp.Write(requestBytes, 0, requestBytes.Length);
            outp.Close();
            HttpWebResponse response = (HttpWebResponse)con.GetResponse();
            if (response.StatusCode != HttpStatusCode.OK)
                throw new IOException(MessageLocalization.GetComposedMessage("invalid.http.response.1", (int)response.StatusCode));
            Stream inp = response.GetResponseStream();

            MemoryStream baos = new MemoryStream();
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = inp.Read(buffer, 0, buffer.Length)) > 0)
            {
                baos.Write(buffer, 0, bytesRead);
            }
            inp.Close();
            response.Close();
            byte[] respBytes = baos.ToArray();

            String encoding = response.ContentEncoding;
            if (encoding != null && Util.EqualsIgnoreCase(encoding, "base64"))
            {
                respBytes = Convert.FromBase64String(Encoding.ASCII.GetString(respBytes));
            }
            return respBytes;
        }
    }
}