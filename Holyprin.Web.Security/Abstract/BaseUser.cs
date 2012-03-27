using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Holyprin.Web.Security
{
	public abstract class BaseUser<TRole, TKey>
	{
		[Key]
		public virtual TKey UserId { get; set; }

		public virtual string Username { get; set; }

		public virtual string Email { get; set; }

		[MaxLength(128)]
		public virtual byte[] PasswordSalt { get; set; }

		[MaxLength(64)]
		public virtual byte[] PasswordHash { get; set; }

		public virtual string PasswordQuestion { get; set; }

		public virtual string PasswordAnswer { get; set; }

		public virtual string Comment { get; set; }

		[Display(Name = "Is Approved?")]
		public virtual bool IsApproved { get; set; }

		[Display(Name = "Date Created")]
		public virtual DateTime DateCreated { get; set; }

		[Display(Name = "Last Activity Date")]
		public virtual DateTime? DateLastActivity { get; set; }

		[Display(Name = "Last Login Date")]
		public virtual DateTime? DateLastLogin { get; set; }

		[Display(Name = "Last Password Change Date")]
		public virtual DateTime DateLastPasswordChange { get; set; }

		public ICollection<TRole> Roles { get; set; }

		protected BaseUser()
		{
			Roles = new List<TRole>();
		}
	}

}
