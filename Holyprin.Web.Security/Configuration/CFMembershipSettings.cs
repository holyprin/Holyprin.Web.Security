using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Reflection;
using System.ComponentModel;
using System.Data.Entity;

namespace Holyprin.Web.Security.Configuration
{
	public class CFMembershipSettings : ConfigurationSection
	{
		public static string UserTable
		{
			get { return settings.userTable; }
		}

		public static string RoleTable
		{
			get { return settings.roleTable; }
		}

		public static Type UserType
		{
			get
			{
				try { return Type.GetType(settings.userObject) ?? null; }
				catch (Exception ex) { throw new ArgumentException("Invalid User object, check your configuration", "userObject", ex); }
			}
		}

		public static Type RoleType
		{
			get
			{
				try { return Type.GetType(settings.roleObject) ?? null; }
				catch (Exception ex) { throw new ArgumentException("Invalid Role object, check your configuration", "roleObject", ex); }
			}

		}

		public static Type DataContext
		{
			get
			{
				try { return Type.GetType(settings.dbContext) ?? null; }
				catch (Exception ex) { throw new ArgumentException("Invalid dbContext object, check your configuration", "dbContext", ex); }
			}
		}

		public static Type ProviderKeyType
		{
			get
			{
				try
				{
					Type type = (settings.keyType.StartsWith("System")) ?
						Type.GetType(settings.keyType) :
						Type.GetType("System." + settings.keyType);

					if (type != typeof(System.Guid) && type != typeof(System.Int32) && type != typeof(System.Int64) && type != typeof(System.Int16))
						throw new ArgumentException("Invalid provider key type, available options are Int16, Int32, Int64, Guid", "keyType");

					return type;
				}
				catch (Exception ex) { throw new ArgumentException("Invalid provider key type, available options are Int16, Int32, Int64, Guid", "keyType", ex); }
			}
		}

		public static bool AllowLoginWithEmail
		{
			get { return Boolean.Parse(settings.allowLoginWithEmail); }
		}

		public static bool UseEmailAsUsername
		{
			get { return Boolean.Parse(settings.useEmailAsUsername); }
		}

		private static CFMembershipSettings settings = ConfigurationManager.GetSection("CFMembershipSettings") as CFMembershipSettings;

		[ConfigurationProperty("dbContext", DefaultValue = "Holyprin.Web.Security.ProviderContext, Holyprin.Web.Security", IsRequired = true)]
		private string dbContext
		{
			get { return this["dbContext"].ToString(); }
			set { this["dbContext"] = value; }
		}

		[ConfigurationProperty("userObject", DefaultValue = "Holyprin.Web.Security.ProviderUser, Holyprin.Web.Security", IsRequired = true)]
		private string userObject
		{
			get { return this["userObject"].ToString(); }
			set { this["userObject"] = value; }
		}

		[ConfigurationProperty("roleObject", DefaultValue = "Holyprin.Web.Security.ProviderRole, Holyprin.Web.Security", IsRequired = true)]
		private string roleObject
		{
			get { return this["roleObject"].ToString(); }
			set { this["roleObject"] = value; }
		}

		[ConfigurationProperty("keyType", DefaultValue = "Guid", IsRequired = true)]
		private string keyType
		{
			get { return this["keyType"].ToString();  }
			set { this["keyType"] = value; }
		}

		[ConfigurationProperty("userTable", DefaultValue = "Users", IsRequired = true)]
		public string userTable
		{
			get { return this["userTable"].ToString(); }
			set { this["userTable"] = value; }
		}

		[ConfigurationProperty("roleTable", DefaultValue = "Roles", IsRequired = true)]
		public string roleTable
		{
			get { return this["roleTable"].ToString(); }
			set { this["roleTable"] = value; }
		}

		[ConfigurationProperty("allowLoginWithEmail", DefaultValue = "true", IsRequired = true)]
		public string allowLoginWithEmail
		{
			get { return this["allowLoginWithEmail"].ToString(); }
			set { this["allowLoginWithEmail"] = value; }
		}

		[ConfigurationProperty("useEmailAsUsername", DefaultValue = "false", IsRequired = true)]
		public string useEmailAsUsername
		{
			get { return this["useEmailAsUsername"].ToString(); }
			set { this["useEmailAsUsername"] = value; }
		}
	}
}
