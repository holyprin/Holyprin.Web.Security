using System;
using System.Collections.Generic;
using System.Linq;
using System.Data.Entity;
using System.Web;
using System.Web.Security;

namespace Holyprin.Web.Security.Web.MembershipCode
{
	public class DbInitializer : DropCreateDatabaseAlways<BaseContext>
	{
		protected override void Seed(BaseContext context)
		{
			var roles = new List<Role> 
			{
				new Role { Name = "Administrator" },
				new Role { Name = "User" },
				new Role { Name = "New" }
			};

			roles.ForEach(r => context.Roles.Add(r));

			context.SaveChanges();
		}
	}
}