using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace Holyprin.Web.Security
{
	public class ProviderRole : IProviderRole<ProviderUser, Guid>
	{
		[Key]
		public Guid RoleId { get; set; }

		public string Name { get; set; }

		public virtual ICollection<ProviderUser> Users { get; set; }
	}
}
