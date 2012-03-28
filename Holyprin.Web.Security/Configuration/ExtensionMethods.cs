// Code-First Membership / Role Provider
// Copyright © Alicia Tams - Holyprin, 2008-2011 | www.aliciatams.com
// Licensed under terms of GNU General Public License version 2 (GPLv2)

using System;
using System.Linq;
using System.Collections.Specialized;
using System.Web.Security;

namespace Holyprin.Web.Security
{
	internal static class ExtensionMethods
	{
		public static bool CheckPasswordPolicy(this MembershipProvider provider, string password)
		{
			// Check length
			if (string.IsNullOrWhiteSpace(password)) return false;
			if (password.Length < provider.MinRequiredPasswordLength) return false;

			// Check non-alphanumeric characters
			int count = password.ToCharArray().Count(x => !char.IsLetterOrDigit(x));
			if (count < provider.MinRequiredNonAlphanumericCharacters) return false;

			// Check regex if required
			if (string.IsNullOrWhiteSpace(provider.PasswordStrengthRegularExpression)) return true;
			return System.Text.RegularExpressions.Regex.IsMatch(password, provider.PasswordStrengthRegularExpression);
		}

		public static string GetConfigValue(this NameValueCollection config, string name, string defaultValue)
		{
			// Validate arguments
			if (config == null) throw new ArgumentNullException("config");
			if (name == null) throw new ArgumentNullException("name");
			if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "name");

			// Check if we have value in collection
			if (Array.IndexOf(config.AllKeys, name) > -1)
			{
				var r = config[name];
				config.Remove(name);
				return r;
			}
			return defaultValue;
		}

		public static int GetConfigValue(this NameValueCollection config, string name, int defaultValue)
		{
			// Validate arguments
			if (config == null) throw new ArgumentNullException("config");
			if (name == null) throw new ArgumentNullException("name");
			if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "name");

			// Check if we have value in collection
			if (Array.IndexOf(config.AllKeys, name) > -1)
			{
				int r;
				var parsed = int.TryParse(config[name], out r);
				if (!parsed) throw new System.Configuration.ConfigurationErrorsException(string.Format("Value of the \"{0}\" attribute is not valid Int32.", name));
				config.Remove(name);
				return r;
			}
			return defaultValue;
		}

		public static bool GetConfigValue(this NameValueCollection config, string name, bool defaultValue)
		{
			// Validate arguments
			if (config == null) throw new ArgumentNullException("config");
			if (name == null) throw new ArgumentNullException("name");
			if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "name");

			// Check if we have value in collection
			if (Array.IndexOf(config.AllKeys, name) > -1)
			{
				bool r;
				var parsed = bool.TryParse(config[name], out r);
				if (!parsed) throw new System.Configuration.ConfigurationErrorsException(string.Format("Value of the \"{0}\" attribute is not valid Boolean.", name));
				config.Remove(name);
				return r;
			}
			return defaultValue;
		}
	}
}

