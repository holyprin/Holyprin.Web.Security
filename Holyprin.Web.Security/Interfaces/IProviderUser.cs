using System;
using System.Collections.Generic;

namespace Holyprin.Web.Security
{
	public interface IProviderUser<TRole, TKey> where TRole : class
	{
		TKey UserId { get; set; }
		string Username { get; set; }
		string Email { get; set; }
		byte[] PasswordSalt { get; set; }
		byte[] PasswordHash { get; set; }
		string PasswordQuestion { get; set; }
		string PasswordAnswer { get; set; }
		string Comment { get; set; }
		bool IsApproved { get; set; }
		DateTime DateCreated { get; set; }
		DateTime? DateLastActivity { get; set; }
		DateTime? DateLastLogin { get; set; }
		DateTime DateLastPasswordChange { get; set; }

		ICollection<TRole> Roles { get; set; }
	}
}
