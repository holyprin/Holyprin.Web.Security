using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Holyprin.Web.Security
{
	public interface IProviderRole<TUser, TKey> where TUser : class
	{
		TKey RoleId { get; set; }

		string Name { get; set; }

		ICollection<TUser> Users { get; set; }
	}
}
