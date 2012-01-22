using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.Entity;

namespace Holyprin.Web.Security.Configuration
{
	public class ProviderContext : DbContext
	{
		public DbSet<ProviderUser> Users { get; set; }
		public DbSet<ProviderRole> Roles { get; set; }

		protected override void OnModelCreating(DbModelBuilder modelBuilder)
		{
			modelBuilder.Entity<ProviderUser>().ToTable(CFMembershipSettings.UserTable);
			modelBuilder.Entity<ProviderRole>().ToTable(CFMembershipSettings.RoleTable);

			modelBuilder.Entity<ProviderUser>()
				.HasMany<ProviderRole>(u => u.Roles)
				.WithMany(r => r.Users)
				.Map(rm => rm.ToTable("RoleMemberships"));

			base.OnModelCreating(modelBuilder);
		}
	}
}
