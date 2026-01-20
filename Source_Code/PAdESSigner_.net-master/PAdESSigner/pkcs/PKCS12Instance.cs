using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace pkcs
{
	class PKCS12Instance : IPKCSInstance
	{
		public string FilePath { get; set; }
		public string KeyStorePassword { get; set; }
	}
}
