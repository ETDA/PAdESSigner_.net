using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using pkcs;
using timestamp;
using utility;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using System.Threading;

namespace sign
{
	class PAdESSigner
	{

		/**
		 * Blank constructor
		 */
		public PAdESSigner()
		{

		}
		/**
		 * Sign a single file
		 * @param inputFilePath
		 * @param outputFilePath
		 * @param pkcsInstance
		 * @param digestAlgorithm
		 * @param signatureAppearance
		 * @param timeStamping
		 * @throws GeneralSecurityException
		 * @throws Exception
		 */
		public void SignOnce(string inputFilePath, string outputFilePath, IPKCSInstance pkcsInstance,
				DigestAlgorithm digestAlgorithm, SignatureAppearance signatureAppearance, TimeStamp timeStamping)
		{
			// Get TimeStamp
			ITSAClient tsaClient = GetTimeStampConnection(timeStamping);

			// Get the certificate chain, private key and key store provider into the CertificateKeyPack instance
			CertificateKeyPack certificateKeyPack = LoadKeyStore(pkcsInstance);
			//ICipherParameters privateKey = certificateKeyPack.PrivateKey;
			X509Certificate[] certificateChain = certificateKeyPack.CertificateChain.ToArray();

			List<string> crlURLList = new List<string>();

			for (int i = 0; i < certificateChain.Length; i++) {
				X509Certificate cert = (X509Certificate)certificateChain[i];
				Console.WriteLine(string.Format("[%s] %s", i, cert.SubjectDN));
				Console.WriteLine("CRL: " + CertificateUtil.GetCRLURL(cert));
				Console.WriteLine("OCSP: " + CertificateUtil.GetOCSPURL(cert));
				crlURLList.Add(CertificateUtil.GetCRLURL(cert));
			}

			// Get OCSP and CRL for long-term validation
			OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(null);
			List<ICrlClient> crlList = new List<ICrlClient>();
			//crlList.add(new CrlClientOnline());
			foreach (string crlURL in crlURLList) {
				crlList.Add(new CrlClientOnline(crlURL));

			}

			//Call SignController class for signing
			SignController signController = new SignController();

			if (certificateKeyPack.CertificateInstance != null)
            {
				signController.Sign(inputFilePath, outputFilePath, certificateChain, certificateKeyPack.CertificateInstance,
					digestAlgorithm, CryptoStandard.CMS,
					signatureAppearance, crlList, ocspClient, tsaClient, 0);
			} 
			else if (certificateKeyPack.PrivateKey != null)
            {
				signController.Sign(inputFilePath, outputFilePath, certificateChain, certificateKeyPack.PrivateKey,
					digestAlgorithm, CryptoStandard.CMS,
				   signatureAppearance, crlList, ocspClient, tsaClient, 0);
			}
			else
            {
				throw new Exception("Unknown error occur");
            }
		}

		/**
		 * Sign multiple file
		 * @param inputFolderPath
		 * @param outputFolderPath
		 * @param outputSuffix
		 * @param pkcsInstance
		 * @param digestAlgorithm
		 * @param signatureAppearance
		 * @param timeStamping
		 * @throws GeneralSecurityException
		 * @throws Exception
		 */
		public void signMultiple(String inputFolderPath, String outputFolderPath, String outputSuffix, IPKCSInstance pkcsInstance,
				DigestAlgorithm digestAlgorithm, SignatureAppearance signatureAppearance, TimeStamp timeStamping)
		{
			// Get TimeStamp
			ITSAClient tsaClient = GetTimeStampConnection(timeStamping);

			// Get the certificate chain, private key and key store provider into the CertificateKeyPack instance
			CertificateKeyPack certificateKeyPack = LoadKeyStore(pkcsInstance);
			//ICipherParameters privateKey = certificateKeyPack.PrivateKey;
			X509Certificate[] certificateChain = certificateKeyPack.CertificateChain.ToArray();

			List<string> crlURLList = new List<string>();

			for (int i = 0; i < certificateChain.Length; i++)
			{
				X509Certificate cert = (X509Certificate)certificateChain[i];
				Console.WriteLine(string.Format("[%s] %s", i, cert.SubjectDN));
				Console.WriteLine("CRL: " + CertificateUtil.GetCRLURL(cert));
				Console.WriteLine("OCSP: " + CertificateUtil.GetOCSPURL(cert));
				crlURLList.Add(CertificateUtil.GetCRLURL(cert));
			}

			// Get OCSP and CRL for long-term validation
			OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(null);
			List<ICrlClient> crlList = new List<ICrlClient>();
			//crlList.add(new CrlClientOnline());
			foreach (string crlURL in crlURLList)
			{
				crlList.Add(new CrlClientOnline(crlURL));

			}

			List<FileSpecification> fileSpecList = GetFileFromFolder(inputFolderPath);

			foreach (FileSpecification fileSpec in fileSpecList)
			{

				Console.WriteLine("Signing: " + fileSpec.FileNameWithExtension);

				string inputFilePath = fileSpec.FullFilePath;
				string outputFilePath = null;
				if (outputSuffix != null)
				{
					outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + outputSuffix + "." + fileSpec.FileExtension;
				}
				else
				{
					outputFilePath = outputFolderPath + "/" + fileSpec.FileNameWithoutExtension + "." + fileSpec.FileExtension;
				}

				//Call SignController class for signing
				SignController signController = new SignController();
				if (certificateKeyPack.CertificateInstance != null)
				{
					signController.Sign(inputFilePath, outputFilePath, certificateChain, certificateKeyPack.CertificateInstance,
						digestAlgorithm, CryptoStandard.CMS,
						signatureAppearance, crlList, ocspClient, tsaClient, 0);
				}
				else if (certificateKeyPack.PrivateKey != null)
				{
					signController.Sign(inputFilePath, outputFilePath, certificateChain, certificateKeyPack.PrivateKey,
						digestAlgorithm, CryptoStandard.CMS,
					   signatureAppearance, crlList, ocspClient, tsaClient, 0);
				}
				else
				{
					throw new Exception("Unknown error occur");
				}
				Console.Out.WriteLine("Wait for 5 seconds...");
				Thread.Sleep(5000);
			}
		}

		/**
		 * Get all file in specific folder
		 * @param folderPath
		 * @return List<FileSpecification>
		 */
		private List<FileSpecification> GetFileFromFolder(string folderPath)
		{

			List<FileSpecification> fileSpecList = new List<FileSpecification>();


			foreach (string file in Directory.GetFiles(folderPath, "*.pdf", SearchOption.AllDirectories))
			{
				FileSpecification fileSpecification = new FileSpecification();
				fileSpecification.FullFilePath = Path.GetFullPath(file);
				fileSpecification.FileNameWithExtension = Path.GetFileName(file);
				fileSpecification.FileNameWithoutExtension = Path.GetFileNameWithoutExtension(file);
				fileSpecification.FileExtension = Path.GetExtension(file);
				fileSpecList.Add(fileSpecification);
			}

			return fileSpecList;
		}

		/**
		 * Get TSA instance
		 * @param timeStamping
		 * @return ITSAClient
		 */
		private ITSAClient GetTimeStampConnection(TimeStamp timeStamp)
		{
			ITSAClient tsaClient = null;
			if (timeStamp == null)
			{
				tsaClient = null;
			}
			else if (timeStamp.TimeStampType == TimeStampType.COMPUTER_CLOCK)
			{
				tsaClient = null;
			}
			else if (timeStamp.TimeStampType == TimeStampType.TSA)
			{
				if (timeStamp.TSAAuthenticationType == TSAAuthenticationType.NO_AUTHENTICATION)
				{
					tsaClient = new TSAClientBouncyCastle(timeStamp.URL, "", "");
				}
				else if (timeStamp.TSAAuthenticationType == TSAAuthenticationType.USERNAME_PASSWORD)
				{
					tsaClient = new TSAClientBouncyCastle(timeStamp.URL, timeStamp.Username, timeStamp.Password);
				}
				else if (timeStamp.TSAAuthenticationType == TSAAuthenticationType.CERTIFICATE)
				{
					tsaClient = new TSAController(timeStamp.URL, timeStamp.CertificatePath, timeStamp.Password, true);
				}
			}

			return tsaClient;
		}

		/**
		 * Get Certificate chain, private key and KeyStore provider from input KeyStore
		 * @param pkcsInstance
		 * @return CertificateKeyPack
		 * @throws Exception
		 */
		private CertificateKeyPack LoadKeyStore(IPKCSInstance pkcsInstance)
		{
			if (pkcsInstance is PKCS12Instance) {

				CertificateKeyPack certificateKeyPack = new CertificateKeyPack();

				char[] passwordCharArr = ((PKCS12Instance)pkcsInstance).KeyStorePassword.ToCharArray();

				// The first argument defines that the keys and certificates are stored using PKCS#12
				Pkcs12Store pk12 = new Pkcs12Store(new FileStream(((PKCS12Instance)pkcsInstance).FilePath, FileMode.Open, FileAccess.Read), passwordCharArr);
				string alias = null;
				foreach (var a in pk12.Aliases)
				{
					alias = ((string)a);
					if (pk12.IsKeyEntry(alias))
						break;
				}

				X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
				List<X509Certificate> chain = new List<X509Certificate>();
				for (int k = 0; k < ce.Length; ++k)
				{
					chain.Add(ce[k].Certificate);
				}

				certificateKeyPack.PrivateKey = pk12.GetKey(alias).Key;
				certificateKeyPack.CertificateChain = chain;

				return certificateKeyPack;

			} else if (pkcsInstance is PKCS11Instance) {
				CertificateKeyPack certificateKeyPack = new CertificateKeyPack();

				X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
				store.Open(OpenFlags.MaxAllowed);

				var  name = new X500DistinguishedName(((PKCS11Instance)pkcsInstance).SearchPhase, X500DistinguishedNameFlags.None).Format(false);
				var certificateList = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, name, false);
				var certificate = certificateList[0];
				
				store.Close();

				if (certificate == null)
                {
					throw new Exception("KeyStore not found");
                }

				var pass = new SecureString();
				char[] array = ((PKCS11Instance)pkcsInstance).Pin.ToCharArray();
				foreach (char ch in array)
				{
					pass.AppendChar(ch);
				}
				var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
				CspParameters cspParameters = new CspParameters(
					privateKey.CspKeyContainerInfo.ProviderType,
					privateKey.CspKeyContainerInfo.ProviderName,
					privateKey.CspKeyContainerInfo.KeyContainerName,
					new System.Security.AccessControl.CryptoKeySecurity(),
					pass);

				var rsaCsp = new RSACryptoServiceProvider(cspParameters);

				certificate.PrivateKey = rsaCsp;

				Org.BouncyCastle.X509.X509Certificate bcCert = DotNetUtilities.FromX509Certificate(certificate);

				certificateKeyPack.PrivateKey = null;
				certificateKeyPack.CertificateInstance = certificate;
				certificateKeyPack.CertificateChain = new List<Org.BouncyCastle.X509.X509Certificate> { bcCert };

				Console.WriteLine(certificateKeyPack.CertificateChain.Count);
				return certificateKeyPack;

			} else {
				throw new Exception("Unrecognized PKCSInstance class");
			}

		}


		// Nested class for store certificate chain and private key element
		internal class CertificateKeyPack
		{
			public ICipherParameters PrivateKey { get; set; }
			public List<Org.BouncyCastle.X509.X509Certificate> CertificateChain { get; set; }
			public X509Certificate2 CertificateInstance { get; set; }

		}
	}


}
