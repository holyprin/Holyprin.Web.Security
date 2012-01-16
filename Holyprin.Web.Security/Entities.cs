using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;

namespace Holyprin.Web.Security
{
	#region Entities...

	public class BaseUser : IUser<BaseRole, Guid>
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

		public virtual ICollection<BaseRole> Roles { get; set; }
	}

	public class BaseRole : IRole<BaseUser, Guid>
	{
		[Key]
		public Guid RoleId { get; set; }

		public string Name { get; set; }

		public virtual ICollection<BaseUser> Users { get; set; }
	}

	#endregion

	#region Interfaces

	public interface IUser<TRole, TKey> where TRole : class
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

	public interface IRole<TUser, TKey> where TUser : class 
	{
		TKey RoleId { get; set; }

		string Name { get; set; }

		ICollection<TUser> Users { get; set; }
	}
	
	#endregion

	#region Context...
	
	public class BaseContext : DbContext
	{
		public DbSet<BaseUser> Users { get; set; }
		public DbSet<BaseRole> Roles { get; set; }

		public BaseContext() : base("ApplicationServices") { }

		protected override void OnModelCreating(DbModelBuilder modelBuilder)
		{
			modelBuilder.Entity<BaseUser>()
				.HasMany<BaseRole>(u => u.Roles)
				.WithMany(r => r.Users)
				.Map(m => m.ToTable("RoleMemberships"));
		}
	}

	public class BaseDbInitializer : DropCreateDatabaseAlways<BaseContext>
	{
		protected override void Seed(BaseContext context)
		{
			context.Roles.Add(new BaseRole { Name = "Test" });
			context.SaveChanges();
			base.Seed(context);
		}
	}

	#endregion
}
