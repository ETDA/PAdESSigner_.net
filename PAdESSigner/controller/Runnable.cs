using pkcs;
using sign;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using timestamp;
using utility;

namespace controller
{
    class Runnable
    {
        public static void Main(string[] args)
        {
			try
			{

				RunWithExternalInput(args);
				
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine(ex.Message);
				Console.Error.WriteLine(ex.StackTrace);
			}
			
			finally
            {
				Console.WriteLine("Press enter to exit");
				Console.Read();
            }
			
		}

		public static void RunWithExternalInput(string[] args)
        {
			ParameterController paramCtrl = new ParameterController(args);

			// Input-Output
			string signType = paramCtrl.getParameterValue("-signType");
			string inputFile = paramCtrl.getParameterValue("-inputFile");
			string outputFile = paramCtrl.getParameterValue("-outputFile");
			string inputFolder = paramCtrl.getParameterValue("-inputFolder");
			string outputFolder = paramCtrl.getParameterValue("-outputFolder");
			string outputSuffix = paramCtrl.getParameterValue("-outputSuffix");

			//PKCS12 Parameter
			string pkcs12FilePath = paramCtrl.getParameterValue("-pkcs12FilePath");
			string pkcs12Password = paramCtrl.getParameterValue("-pkcs12Password");

			//PKCS11 Parameter
			string pkcs11TokenName = paramCtrl.getParameterValue("-pkcs11TokenName");
			string pkcs11LibraryPath = paramCtrl.getParameterValue("-pkcs11LibraryPath");
			string pkcs11TokenPin = paramCtrl.getParameterValue("-pkcs11Pin");
			string pkcs11KeyStorePassword = paramCtrl.getParameterValue("-pkcs11KeyStorePassword");
			string pkcs11SearchKeyword = paramCtrl.getParameterValue("-pkcs11SeachKeyword");

			//TimeStamp URL
			TimeStampType timeStampingType = (TimeStampType)(paramCtrl.getParameterValue("-timeStampType") != null ? Enum.Parse(typeof(TimeStampType), paramCtrl.getParameterValue("-timeStampType")) : null);
			TSAAuthenticationType tsaAuthenticationType = TSAAuthenticationType.NO_AUTHENTICATION;
			if (paramCtrl.getParameterValue("-tsaAuthenticationType") != null) {
				switch(paramCtrl.getParameterValue("-tsaAuthenticationType"))
                {
					case "NO_AUTHENTICATION":
						tsaAuthenticationType = TSAAuthenticationType.NO_AUTHENTICATION;
						break;
					case "USERNAME_PASSWORD":
						tsaAuthenticationType = TSAAuthenticationType.USERNAME_PASSWORD;
						break;
					case "CERTIFICATE":
						tsaAuthenticationType = TSAAuthenticationType.CERTIFICATE;
						break;
				}
            }
			//TSAAuthenticationType tsaAuthenticationType = (TSAAuthenticationType)(paramCtrl.getParameterValue("-tsaAuthenticationType") != null ? Enum.Parse(typeof(TSAAuthenticationType), paramCtrl.getParameterValue("-tsaAuthenticationType")) : null);
			string tsaURL = paramCtrl.getParameterValue("-tsaURL");
			string tsaUsername = paramCtrl.getParameterValue("-tsaUsername");
			string tsaPassword = paramCtrl.getParameterValue("-tsaPassword");
			string tsaPKCS12File = paramCtrl.getParameterValue("-tsaPKCS12File");
			string tsaPKCS12Password = paramCtrl.getParameterValue("-tsaPKCS12Password");
			TimeStamp timeStamping;
			if (timeStampingType == TimeStampType.TSA)
			{
				switch (tsaAuthenticationType)
				{
					case TSAAuthenticationType.NO_AUTHENTICATION:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType
						};
						break;
					case TSAAuthenticationType.USERNAME_PASSWORD:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType,
							Username = tsaUsername,
							Password = tsaPassword
						};
						break;
					case TSAAuthenticationType.CERTIFICATE:
						timeStamping = new TimeStamp()
						{
							TimeStampType = timeStampingType,
							URL = tsaURL,
							TSAAuthenticationType = tsaAuthenticationType,
							CertificatePath = tsaPKCS12File,
							Password = tsaPKCS12Password
						};
						break;
					default:
						throw new Exception("TSA authentication must be input");
				}
			} 
			else if (timeStampingType == TimeStampType.COMPUTER_CLOCK)
			{
				timeStamping = new TimeStamp()
				{
					TimeStampType = timeStampingType
				};
			}
			else
            {
				timeStamping = new TimeStamp()
				{
					TimeStampType = timeStampingType
				};
			}
			//Signature Appearance
			SignatureAppearance signatureAppearance = new SignatureAppearance();
			signatureAppearance.Location = (paramCtrl.getParameterValue("-Location"));
			signatureAppearance.Reason = (paramCtrl.getParameterValue("-Reason"));
			signatureAppearance.X = (int.Parse(paramCtrl.getParameterValue("-X")));
			signatureAppearance.Y = (int.Parse(paramCtrl.getParameterValue("-Y")));
			signatureAppearance.Width = (int.Parse(paramCtrl.getParameterValue("-Width")));
			signatureAppearance.Height = (int.Parse(paramCtrl.getParameterValue("-Height")));
			signatureAppearance.SignatureFieldName = (paramCtrl.getParameterValue("-SignatureFieldName"));
			signatureAppearance.PageNumber = (int.Parse(paramCtrl.getParameterValue("-PageNumber")));
			signatureAppearance.SignatureLevel = ((SignatureLevel)(paramCtrl.getParameterValue("-SignatureLevel") != null ? Enum.Parse(typeof(SignatureLevel), paramCtrl.getParameterValue("-SignatureLevel")) : null));
			signatureAppearance.SignatureVisibility = ((SignatureVisibility)(paramCtrl.getParameterValue("-SignatureVisibility") != null ? Enum.Parse(typeof(SignatureVisibility), paramCtrl.getParameterValue("-SignatureVisibility")) : null));
			signatureAppearance.SignaturePattern = ((SignaturePattern)(paramCtrl.getParameterValue("-SignaturePattern") != null ? Enum.Parse(typeof(SignaturePattern), paramCtrl.getParameterValue("-SignaturePattern")) : null));
			signatureAppearance.SignatureImage = (paramCtrl.getParameterValue("-SignatureImage"));

			//Other sign parameter
			DigestAlgorithm digestAlgorithm = (DigestAlgorithm)(paramCtrl.getParameterValue("-digestAlgorithm") != null ? Enum.Parse(typeof(DigestAlgorithm),paramCtrl.getParameterValue("-digestAlgorithm")) : null);

			//PKCS
			PKCS12Instance pkcs12 = null;
			PKCS11Instance pkcs11 = null;

			if (pkcs12FilePath != null && pkcs12Password != null)
			{
				pkcs12 = new PKCS12Instance() {
					FilePath = pkcs12FilePath, 
					KeyStorePassword = pkcs12Password 
				};
			}
			//else if (pkcs11TokenName != null && pkcs11LibraryPath != null && pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null)
			else if (pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null)
			{
				pkcs11 = new PKCS11Instance() { 
					TokenName = pkcs11TokenName, 
					Pin =  pkcs11TokenPin, 
					KeyStorePassword = pkcs11KeyStorePassword, 
					SearchPhase = pkcs11SearchKeyword 
				};
			}
			else
			{
				throw new Exception("Incomplete certificate input");
			}

			//Let's sign
			PAdESSigner padesSigner = new PAdESSigner();
			if (signType.Equals("single"))
			{
				if (pkcs12 != null)
				{
					padesSigner.SignOnce(inputFile, outputFile, pkcs12, digestAlgorithm, signatureAppearance, timeStamping);
				}
				else if ((pkcs11 != null))
				{
					padesSigner.SignOnce(inputFile, outputFile, pkcs11, digestAlgorithm, signatureAppearance, timeStamping);
				}
			}
			else if (signType.Equals("multiple"))
			{
				if (pkcs12 != null)
				{
					padesSigner.signMultiple(inputFolder, outputFolder, outputSuffix, pkcs12, digestAlgorithm, signatureAppearance, timeStamping);
				}
				else if ((pkcs11 != null))
				{
					padesSigner.signMultiple(inputFolder, outputFolder, outputSuffix, pkcs11, digestAlgorithm, signatureAppearance, timeStamping);
				}
			}
			else
			{
				throw new Exception("Sign type must be 'single' or 'multiple only'");
			}

			Console.WriteLine("Complete");
		}
    }
}
