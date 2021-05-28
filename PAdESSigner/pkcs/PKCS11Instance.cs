using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace pkcs
{
    class PKCS11Instance : IPKCSInstance
    {
        public string LibraryPath { get; set; }
        public string KeyStorePassword { get; set; }
        public string TokenName { get; set; }
        public string Pin { get; set; }
        public int Slot { get; set; }
        public string SearchPhase { get; set; }
    }
}
