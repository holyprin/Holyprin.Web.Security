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

		protected override void InitializeDefault()
		{
			base.InitializeDefault();
		}

		[ConfigurationProperty("dbContext", DefaultValue = "Holyprin.Web.Security.BaseContext, Holyprin.Web.Security", IsRequired = false)]
		[TypeConverter("Holyprin.Web.Security.StringToAssemblyTypeConverter, Holyprin.Web.Security")]
		public Type dbContext
		{
			get{ return Type.GetType(this["dbContext"].ToString()); }
			set { this["dbContext"] = Type.GetType(value.ToString()); }
		}

		[ConfigurationProperty("userObject", DefaultValue = "Holyprin.Web.Security.User, Holyprin.Web.Security", IsRequired = false)]
		[TypeConverter("Holyprin.Web.Security.StringToAssemblyTypeConverter, Holyprin.Web.Security")]
		public Type userObject
		{
			get { return Type.GetType(this["userObject"].ToString()); }
			set { this["userObject"] = Type.GetType(value.ToString()); }
		}

		[ConfigurationProperty("roleObject", DefaultValue = "Holyprin.Web.Security.Role, Holyprin.Web.Security", IsRequired = false)]
		[TypeConverter("Holyprin.Web.Security.StringToAssemblyTypeConverter, Holyprin.Web.Security")]
		public Type roleObject
		{
			get { return Type.GetType(this["roleObject"].ToString()); }
			set { this["roleObject"] = Type.GetType(value.ToString()); }
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

	public class StringToAssemblyTypeConverter : TypeConverter
	{
		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
		{
			if (sourceType == typeof(string))
				return true;
			return base.CanConvertFrom(context, sourceType);
		}
		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
		{
			if (destinationType == typeof(Type))
				return true;
			return base.CanConvertTo(context, destinationType);
		}
		public override object ConvertFrom(ITypeDescriptorContext context, System.Globalization.CultureInfo culture, object value)
		{
			if (value is string)
				return Type.GetType(value.ToString());
			return base.ConvertFrom(context, culture, value);
		}
		public override bool IsValid(ITypeDescriptorContext context, object value)
		{
			if (value is string && value.ToString().Split(',').Count() > 2)
				return true;
			return base.IsValid(context, value);
		}
	}
}
