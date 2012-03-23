using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.Entity;
using System.Web.Security;
using Holyprin.Web.Security;
using Holyprin.Web.Security.MVC3.Entities;
using System.Threading;

namespace Holyprin.Web.Security.MVC3.MembershipCode
{
	public class MyBaseContext : DbContext
	{
		public DbSet<User> Users { get; set; }
		public DbSet<Role> Roles { get; set; }

		public MyBaseContext() : base("ApplicationServicesExpress") { }
	}
	
	public class DbInitializer : DropCreateDatabaseAlways<MyBaseContext>
	{
		protected override void Seed(MyBaseContext context)
		{
			var roles = new List<Role> 
			{
				new Role { Name = "Administrator", RoleId = Guid.NewGuid() },
				new Role { Name = "User", RoleId = Guid.NewGuid() },
				new Role { Name = "New", RoleId = Guid.NewGuid() },
				new Role { Name = "Role1", RoleId = Guid.NewGuid() },
				new Role { Name = "Role2", RoleId = Guid.NewGuid() },
				new Role { Name = "Role3", RoleId = Guid.NewGuid() }
			};

			roles.ForEach(r => context.Roles.Add(r));

			context.SaveChanges();

			MembershipCreateStatus status = new MembershipCreateStatus();

			var memUser = Membership.CreateUser("Demo", "demo1234", "demo@gmail.com");

			for (int i = 1; i <= 3; i++)
			{
				Membership.CreateUser("User" + i.ToString(), "user1234" + i.ToString(), "user" + i.ToString() + "@gmail.com");
			}
			if (status == MembershipCreateStatus.Success)
			{
				User user = context.Users.Find(memUser.ProviderUserKey);
				Role newRole = context.Roles.FirstOrDefault(r => r.Name == "New");

				user.Roles = new List<Role>
				{
					newRole
				};

				user.ExtraField = "Testing Demo";
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
				user.ExtraField = "Testing Admin";
			}

			context.SaveChanges();

			//Thread testing for provider, do not keep, using new threads for max memory usage, if you need to use basic threading, use the threadpool.
			/*Thread xThread = new Thread(new ThreadStart(
				delegate
				{
					MembershipCreateStatus stat = new MembershipCreateStatus();
					for (int i = 0; i <= 100; i++)
					{
						Membership.CreateUser("TestX" + i.ToString(), "Testing1234", "holyprin" + i.ToString() + "x@gmail.com", null, null, true, null, out stat);
					}
				}
			));
			xThread.Start();

			Thread yThread = new Thread(new ThreadStart(
				delegate
				{
					MembershipCreateStatus stat = new MembershipCreateStatus();
					for (int i = 0; i <= 100; i++)
					{
						Membership.CreateUser("TestY" + i.ToString(), "Testing1234", "holyprin" + i.ToString() + "y@gmail.com", null, null, true, null, out stat);
					}
				}
			));
			yThread.Start();
			*/

			base.Seed(context);
		}
	}
}