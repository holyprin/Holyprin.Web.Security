using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace Holyprin.Web.Security
{
	public class ProviderUser : IProviderUser<ProviderRole, Guid>
	{
		[Key]
		public Guid UserId { get; set; }

		public string Username { get; set; }

		public string Email { get; set; }

		[MaxLength(128)]
		public byte[] PasswordSalt { get; set; }

		[MaxLength(64)]
		public byte[] PasswordHash { get; set; }

		public string PasswordQuestion { get; set; }

		public string PasswordAnswer { get; set; }

		public string Comment { get; set; }

		[Display(Name = "Is Approved?")]
		public bool IsApproved { get; set; }

		[Display(Name = "Date Created")]
		public DateTime DateCreated { get; set; }

		[Display(Name = "Last Activity Date")]
		public DateTime? DateLastActivity { get; set; }

		[Display(Name = "Last Login Date")]
		public DateTime? DateLastLogin { get; set; }

		[Display(Name = "Last Password Change Date")]
		public DateTime DateLastPasswordChange { get; set; }

		public virtual ICollection<ProviderRole> Roles { get; set; }
	}

}
