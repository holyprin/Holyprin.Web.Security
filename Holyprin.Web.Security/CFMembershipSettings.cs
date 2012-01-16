using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Reflection;
using System.ComponentModel;

namespace Holyprin.Web.Security
{
	public class CFMembershipSettings : ConfigurationSection
	{
		private static CFMembershipSettings settings = ConfigurationManager.GetSection("CFMembershipSettings") as CFMembershipSettings;

		public static CFMembershipSettings Settings
		{
			get { return settings; }
		}

		[ConfigurationProperty("dbContext", DefaultValue = "Holyprin.Web.Security.BaseContext, Holyprin.Web.Security", IsRequired = false)]
		public string dbContext
		{
			get { return this["dbContext"].ToString(); }
			set { this["dbContext"] = value; }
		}

		[ConfigurationProperty("userObject", DefaultValue = "Holyprin.Web.Security.BaseUser, Holyprin.Web.Security", IsRequired = false)]
		public string userObject
		{
			get { return this["userObject"].ToString(); }
			set { this["userObject"] = value; }
		}

		[ConfigurationProperty("roleObject", DefaultValue = "Holyprin.Web.Security.BaseRole, Holyprin.Web.Security", IsRequired = false)]
		public string roleObject
		{
			get { return this["roleObject"].ToString(); }
			set { this["roleObject"] = value; }
		}

		[ConfigurationProperty("keyType", DefaultValue = "Guid", IsRequired = false)]
		public string keyType
		{
			get { return this["keyType"].ToString();  }
			set { this["keyType"] = value; }
		}

		[ConfigurationProperty("userTableName", DefaultValue = "Users", IsRequired = false)]
		public string userTableName
		{
			get { return this["userTableName"].ToString(); }
			set { this["userTableName"] = value; }
		}

		[ConfigurationProperty("roleTableName", DefaultValue = "Roles", IsRequired = false)]
		public string roleTableName
		{
			get { return this["roleTableName"].ToString(); }
			set { this["roleTableName"] = value; }
		}
	}
}
