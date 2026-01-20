/**
 * Enumerated for Signature level
 * @author ETDA
 *
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace sign
{
	enum SignatureLevel
	{
		APPROVAL,
		CERTIFIED_NO_CHANGES_ALLOW,
		CERTIFIED_FORM_FILLING,
		CERTIFIED_FORM_FILLING_AND_ANNOTATIONS
	}
}
