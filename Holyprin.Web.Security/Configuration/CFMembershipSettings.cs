using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Reflection;
using System.ComponentModel;

namespace Holyprin.Web.Security.Configuration
{
	public class CFMembershipSettings : ConfigurationSection
	{
		private static CFMembershipSettings settings = ConfigurationManager.GetSection("CFMembershipSettings") as CFMembershipSettings;

		public static CFMembershipSettings Settings
		{
			get { return settings; }
		}

		[ConfigurationProperty("dbContext", DefaultValue = "Holyprin.Web.Security.ProviderContext, Holyprin.Web.Security", IsRequired = false)]
		private string dbContext
		{
			get { return this["dbContext"].ToString(); }
			set { this["dbContext"] = value; }
		}

		[ConfigurationProperty("userObject", DefaultValue = "Holyprin.Web.Security.ProviderUser, Holyprin.Web.Security", IsRequired = false)]
		private string userObject
		{
			get { return this["userObject"].ToString(); }
			set { this["userObject"] = value; }
		}

		[ConfigurationProperty("roleObject", DefaultValue = "Holyprin.Web.Security.ProviderRole, Holyprin.Web.Security", IsRequired = false)]
		private string roleObject
		{
			get { return this["roleObject"].ToString(); }
			set { this["roleObject"] = value; }
		}

		[ConfigurationProperty("keyType", DefaultValue = "Guid", IsRequired = false)]
		private string keyType
		{
			get { return this["keyType"].ToString();  }
			set { this["keyType"] = value; }
		}

		[ConfigurationProperty("userTable", DefaultValue = "Users", IsRequired = false)]
		public string UserTable
		{
			get { return this["userTable"].ToString(); }
			set { this["userTable"] = value; }
		}

		[ConfigurationProperty("roleTable", DefaultValue = "Roles", IsRequired = false)]
		public string RoleTable
		{
			get { return this["roleTable"].ToString(); }
			set { this["roleTable"] = value; }
		}

		public Type UserType
		{
			get { return Type.GetType(userObject); }
		}
		
		public Type RoleType
		{
			get { return Type.GetType(roleObject); }
		}

		public Type DataContext
		{
			get { return Type.GetType(dbContext); }
		}

		public Type ProviderKeyType
		{
			get
			{
				return (CFMembershipSettings.Settings.keyType.StartsWith("System")) ?
					Type.GetType(CFMembershipSettings.Settings.keyType) :
					Type.GetType("System." + CFMembershipSettings.Settings.keyType);
			}
		}
	}
}
