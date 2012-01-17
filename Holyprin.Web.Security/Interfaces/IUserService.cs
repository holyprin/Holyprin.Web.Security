using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;

namespace Holyprin.Web.Security.Interfaces
{
	public interface IUserService
	{
		MembershipUser CreateUser();
	}
}
