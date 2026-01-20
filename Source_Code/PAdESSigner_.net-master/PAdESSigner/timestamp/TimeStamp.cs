using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace timestamp
{
    class TimeStamp
    {
        public TSAAuthenticationType TSAAuthenticationType { get; set; }
        public TimeStampType TimeStampType { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string CertificatePath { get; set; }
        public string URL { get; set; }
    }
}
