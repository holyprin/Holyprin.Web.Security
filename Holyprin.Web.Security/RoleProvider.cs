using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;
using Holyprin.Web.Security.Configuration;
using System.Data.Entity;

namespace Holyprin.Web.Security
{
    public class CFRoleProvider : RoleProvider
    {
		private string userTableName, roleTableName;

		public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
		{
			this.ApplicationName = config.GetConfigValue("applicationName", null);
			this.userTableName = CFMembershipSettings.UserTable ?? "Users";
			this.roleTableName = CFMembershipSettings.RoleTable ?? "Roles";

			base.Initialize(name, config);
		}

		public override string ApplicationName { get; set; }

		public string UserTableName { get { return this.userTableName; } }

		public string RoleTableName { get { return this.roleTableName; } }
		
		public override void AddUsersToRoles(string[] usernames, string[] roleNames)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			try
			{
				foreach (string roleStr in roleNames)
				{
					dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleStr)).Cast<dynamic>().FirstOrDefault();

					if (role != null)
					{
						foreach (string userStr in usernames)
						{
							dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE UserName = @user"), new System.Data.SqlClient.SqlParameter("@user", userStr)).Cast<dynamic>().FirstOrDefault();

							if (user != null)
								if (!role.Users.Contains(user))
									role.Users.Add(user);
						}
					}
				}

				DataContext.SaveChanges();
			}
			catch (Exception)
			{
				throw;
			}
			
			DataContext.Dispose();
		}

		public override void CreateRole(string roleName)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			var checkRole = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();
			if (checkRole != null)
				throw new ArgumentException(string.Format("The role: {0} already exists", roleName));

			dynamic role = Activator.CreateInstance(CFMembershipSettings.RoleType);

			//If using SqlServeCE or the UserId is missing the DatabaseGenerated attribute
			//automatically generate keys via code, otherwise allow the server to generate them.
			if (CFMembershipSettings.ProviderKeyType == typeof(Guid))
			{
				var info = (CFMembershipSettings.UserType).GetProperty("UserId").GetCustomAttributesData()
					.SingleOrDefault(item => item.Constructor.ReflectedType.Name == "DatabaseGeneratedAttribute");

				if (info == null)
					role.RoleId = Guid.NewGuid();
			}

			role.Name = roleName;

			Roles.Add(role);

			DataContext.SaveChanges();

			DataContext.Dispose();
		}

		public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			try
			{
				dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();
				if (role != null)
				{
					if (role.Users.Count() > 0 && throwOnPopulatedRole)
						throw new Exception(string.Format("Role: {0} contains users. Will not delete", roleName));
					
					role.Users.Clear();
					
					DataContext.SaveChanges();
				}
			}
			catch (Exception)
			{
				return false;
			}
			
			DataContext.Dispose();
			
			return true;
		}

		public override string[] FindUsersInRole(string roleName, string usernameToMatch)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();
			if (role != null)
			{
				List<string> users = new List<string>();
				foreach (dynamic user in role.Users)
				{
					if (usernameToMatch == user.Username)
						users.Add(user.Username);
				}

				DataContext.Dispose();

				return users.ToArray();
			}

			DataContext.Dispose();

			return null;
		}

		public override string[] GetAllRoles()
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			var result = DataContext.Database.SqlQuery(typeof(string), q("SELECT Name FROM $Roles")).Cast<string>().ToArray();

			DataContext.Dispose();

			return result;
		}

		public override string[] GetRolesForUser(string username)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			List<string> roles = new List<string>();

			var user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();
			if (user != null)
			{
				foreach(dynamic role in user.Roles) {
					roles.Add(role.Name);
				}
			}

			DataContext.Dispose();

			return roles.ToArray();
		}

		public override string[] GetUsersInRole(string roleName)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			List<string> users = new List<string>();

			var role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();
			if (role != null)
			{
				foreach (dynamic user in role.Users)
				{
					users.Add(user.Username);
				}
			}

			DataContext.Dispose();

			return users.ToArray();
		}

		public override bool IsUserInRole(string username, string roleName)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();
			dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();

			if (user != null && role != null)
				return user.Roles.Contains(role);

			DataContext.Dispose();

			return false;
		}

		public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			try
			{
				foreach (string roleStr in roleNames)
				{
					dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleStr)).Cast<dynamic>().FirstOrDefault();
					if (role != null)
					{
						foreach (string userStr in usernames)
						{
							dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"),new System.Data.SqlClient.SqlParameter("@username", userStr)).Cast<dynamic>().FirstOrDefault();
							if (user != null)
								if (role.Users.Contains(user))
									role.Users.Remove(user);
						}
					}
				}
				DataContext.SaveChanges();

				DataContext.Dispose();
			}
			catch (Exception)
			{
				throw;
			}	
		}

		public override bool RoleExists(string roleName)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType), Roles = DataContext.Set(CFMembershipSettings.RoleType);

			dynamic role = Roles.SqlQuery(q("SELECT * FROM $Roles WHERE Name = @role"), new System.Data.SqlClient.SqlParameter("@role", roleName)).Cast<dynamic>().FirstOrDefault();

			DataContext.Dispose();

			return (role != null) ? true : false;
		}

		private string q(string Query, params object[] paramerters)
		{
			return string.Format(Query.Replace("$Users", this.UserTableName).Replace("$Roles", this.RoleTableName), paramerters);
		}
	}
}
