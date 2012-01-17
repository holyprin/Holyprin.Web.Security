using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.Entity;
using System.Web.Security;
using Holyprin.Web.Security;
using Holyprin.Web.Security.MVC3.Entities;

namespace Holyprin.Web.Security.MVC3.MembershipCode
{
	public class MyBaseContext : DbContext
	{
		public DbSet<User> Users { get; set; }
		public DbSet<Role> Roles { get; set; }

		public MyBaseContext() : base("ApplicationServices") { }
	}
	
	public class DbInitializer : DropCreateDatabaseAlways<MyBaseContext>
	{
		protected override void Seed(MyBaseContext context)
		{
			var roles = new List<Role> 
			{
				new Role { Name = "Administrator" },
				new Role { Name = "User" },
				new Role { Name = "New" }
			};

			roles.ForEach(r => context.Roles.Add(r));

			context.SaveChanges();

			MembershipCreateStatus status = new MembershipCreateStatus();

			var memUser = Membership.CreateUser("Demo", "demo1234", "demo@gmail.com");
			if (status == MembershipCreateStatus.Success)
			{
				User user = context.Users.Find(memUser.ProviderUserKey);
				Role newRole = context.Roles.FirstOrDefault(r => r.Name == "New");


				user.Roles = new List<Role>
				{
					newRole
				};

				user.Testing = "Testing Demo";
			}

			memUser = Membership.CreateUser("Admin", "admin123", "admin@gmail.com");
			if (status == MembershipCreateStatus.Success)
			{
				User user = context.Users.Find(memUser.ProviderUserKey);
				Role adminRole = context.Roles.FirstOrDefault(r => r.Name == "Administrator");
				Role userRole = context.Roles.FirstOrDefault(r => r.Name == "User");

				user.Roles = new List<Role>
				{
					adminRole,
					userRole
				};
				user.Testing = "Testing Admin";
			}

			context.SaveChanges();

			base.Seed(context);
		}
	}
}