using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace sign
{
    class SignatureAppearance
    {
		public float X { get; set; }
		public float Y { get; set; }
		public float Width { get; set; }
		public float Height { get; set; }
		public int PageNumber { get; set; }
		public string SignatureFieldName { get; set; }
		public string Reason { get; set; }
		public string Location { get; set; }
		public SignatureLevel SignatureLevel { get; set; }
		public SignaturePattern SignaturePattern { get; set; }
		public string SignatureImage { get; set; }
		public SignatureVisibility SignatureVisibility { get; set; }
	}
}
