using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Holyprin.Web.Security
{
	public abstract class BaseRole<TUser, TKey>
	{
		[Key]
		public virtual TKey RoleId { get; set; }

		public virtual string Name { get; set; }

		public ICollection<TUser> Users { get; set; }

		protected BaseRole()
		{
			Users = new List<TUser>();
		}
	}
}
