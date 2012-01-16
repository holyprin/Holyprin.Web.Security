using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;
using System.Data.Entity;
using System.Text.RegularExpressions;

namespace Holyprin.Web.Security
{
	public class CFMembershipProvider : MembershipProvider
	{
		private Type membership_key_type;
		public static DbContext DataContext;
		public DbSet Users, Roles;

		private string emailRegularExpression, passwordStrengthRegularExpression, userTableName, roleTableName;
		private int minRequiredNonAlphanumericCharacters, minRequiredPasswordLength, generatedPassLength, generatedNonAlpha;
		private bool requiresUniqueEmail, allowLoginWithEmail, useEmailAsUsername, requiresQuestionAndAnswer, enablePasswordReset;

		// Best possible email validation I could find. supports all types.
		public const string DEFAULT_EMAIL_REGEX = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\""
			+ "(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\""
			+ ")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|"
			+ "[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\"
			+ "x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";

		public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
		{
			if (config != null)
				this.ApplicationName = config.GetConfigValue("applicationName", null);
			else
				throw new ArgumentNullException("config");

			this.minRequiredNonAlphanumericCharacters = config.GetConfigValue("minRequiredNonAlphanumericCharacters", 0);
			this.minRequiredPasswordLength = config.GetConfigValue("minRequiredPasswordLength", 8);
			this.passwordStrengthRegularExpression = config.GetConfigValue("passwordStrengthRegularExpression", null);
			this.requiresUniqueEmail = config.GetConfigValue("requiresUniqueEmail", true);
			this.allowLoginWithEmail = config.GetConfigValue("allowLoginWithEmail", true);
			this.useEmailAsUsername = config.GetConfigValue("useEmailAsUsername", false);
			this.generatedNonAlpha = config.GetConfigValue("generatedNonAlpha", 6);
			this.generatedPassLength = config.GetConfigValue("generatedPassLength", 12);
			this.emailRegularExpression = config.GetConfigValue("emailRegularExpression", DEFAULT_EMAIL_REGEX);
			this.requiresQuestionAndAnswer = config.GetConfigValue("requiresQuestionAndAnswer", false);
			this.enablePasswordReset = config.GetConfigValue("enablePasswordReset", true);
			this.userTableName = CFMembershipSettings.Settings.userTableName;
			this.roleTableName = CFMembershipSettings.Settings.roleTableName;

			if (DataContext == null)
				DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.Settings.dbContext);

			if (Users == null)
				Users = DataContext.Set(CFMembershipSettings.Settings.userObject);

			if (Roles == null)
				Roles = DataContext.Set(CFMembershipSettings.Settings.roleObject);

			membership_key_type = (CFMembershipSettings.Settings.keyType.StartsWith("System")) ? Type.GetType(CFMembershipSettings.Settings.keyType) : Type.GetType("System." + CFMembershipSettings.Settings.keyType);

			base.Initialize(name, config);

		}

		#region Properties...

		public override string ApplicationName { get; set; }

		public override bool EnablePasswordReset
		{
			get { return enablePasswordReset; }
		}

		public override int MinRequiredNonAlphanumericCharacters
		{
			get { return minRequiredNonAlphanumericCharacters; }
		}

		public override int MinRequiredPasswordLength
		{
			get { return minRequiredPasswordLength; }
		}

		public override string PasswordStrengthRegularExpression
		{
			get { return passwordStrengthRegularExpression; }
		}

		public override bool RequiresQuestionAndAnswer
		{
			get { return requiresQuestionAndAnswer; }
		}

		public override bool RequiresUniqueEmail
		{
			get { return requiresUniqueEmail; }
		}

		public string EmailRegularExpression { get { return this.emailRegularExpression; } }

		public bool UseEmailAsUsername { get { return this.useEmailAsUsername; } }

		public bool AllowLoginWithEmail { get { return this.allowLoginWithEmail; } }

		public string UserTableName { get { return this.userTableName; } }

		public string RoleTableName { get { return this.roleTableName; } }

		#endregion

		#region CUD Methods...

		public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
		{
			status = MembershipCreateStatus.Success;

			if (string.IsNullOrEmpty(username) || string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(password))
				throw new ArgumentNullException("password");
			if (string.IsNullOrEmpty(email) || string.IsNullOrWhiteSpace(email))
				throw new ArgumentNullException("email");

			if (this.RequiresQuestionAndAnswer)
			{
				if (string.IsNullOrEmpty(passwordQuestion) || string.IsNullOrWhiteSpace(passwordQuestion))
					throw new ArgumentNullException("passwordQuestion");
				if (string.IsNullOrEmpty(passwordAnswer) || string.IsNullOrWhiteSpace(passwordAnswer))
					throw new ArgumentNullException("passwordAnswer");
			}

			if (username.Length > 100)
				status = MembershipCreateStatus.InvalidUserName;

			if (!this.CheckPasswordPolicy(password))
				status = MembershipCreateStatus.InvalidPassword;

			var args = new ValidatePasswordEventArgs(username, password, true);
			this.OnValidatingPassword(args);
			if (args.Cancel)
			{
				if (args.FailureInformation != null) throw args.FailureInformation;
				status = MembershipCreateStatus.InvalidPassword;
			}

			if (!Regex.IsMatch(email, this.EmailRegularExpression))
				status = MembershipCreateStatus.InvalidEmail;

			if (this.UseEmailAsUsername)
				username = email;

			if (this.RequiresUniqueEmail && this.GetUserNameByEmail(email).Trim().Length > 0)
				status = MembershipCreateStatus.DuplicateEmail;

			if (this.GetUser(username, false) != null)
				status = MembershipCreateStatus.DuplicateUserName;

			if (providerUserKey != null && this.GetUser(providerUserKey, false) != null)
				status = MembershipCreateStatus.DuplicateProviderUserKey;

			if (status == MembershipCreateStatus.Success)
			{
				byte[] passwordSalt, passwordHash;
				Guid guid;

				HashPassword(password, out passwordSalt, out passwordHash);

				dynamic usr = Activator.CreateInstance(CFMembershipSettings.Settings.userObject);

				if (providerUserKey != null && Guid.TryParse(providerUserKey.ToString(), out guid))
				{
					usr.UserId = (Guid)providerUserKey;
				}

				usr.Username = username;
				usr.PasswordHash = passwordHash;
				usr.PasswordSalt = passwordSalt;
				usr.PasswordQuestion = passwordQuestion;
				usr.PasswordAnswer = passwordAnswer;
				usr.DateLastPasswordChange = DateTime.Now;
				usr.DateCreated = DateTime.Now;
				usr.DateLastActivity = null;
				usr.DateLastLogin = null;
				usr.Email = email;
				usr.Comment = null;
				usr.IsApproved = isApproved;

				try
				{
					Users.Add(usr);
				}
				catch (Exception)
				{
					status = MembershipCreateStatus.UserRejected;
				}
				try
				{
					int test = DataContext.SaveChanges();
					var blah = test;
				}
				catch (Exception)
				{
					status = MembershipCreateStatus.ProviderError;
				}
				return this.GetUser(usr.UserId, false);
			}
			return null;
		}

		public override bool DeleteUser(string username, bool deleteAllRelatedData)
		{
			throw new NotImplementedException();
		}

		public override void UpdateUser(MembershipUser user)
		{
			throw new NotImplementedException();
		}

		public override bool ValidateUser(string username, string password)
		{
			throw new NotImplementedException();
		}

		public override string ResetPassword(string username, string answer)
		{
			throw new NotImplementedException();
		}

		public override bool ChangePassword(string username, string oldPassword, string newPassword)
		{
			throw new NotImplementedException();
		}

		public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			throw new NotImplementedException();
		}

		#endregion

		#region Select Methods...

		public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			throw new NotImplementedException();
		}

		public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			throw new NotImplementedException();
		}

		public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
		{
			throw new NotImplementedException();
		}

		public override int GetNumberOfUsersOnline()
		{
			throw new NotImplementedException();
		}

		public override MembershipUser GetUser(string username, bool userIsOnline)
		{
			if (string.IsNullOrEmpty(username) || string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");

			dynamic list = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = '{0}'", username));

			foreach (dynamic usr in list)
			{
				MembershipUser memUser = new MembershipUser(
					this.Name,
					usr.Username,
					usr.UserId,
					usr.Email,
					usr.PasswordQuestion == null ? "" : usr.PasswordQuestion,
					usr.Comment == null ? "" : usr.Comment,
					usr.IsApproved,
					false,
					usr.DateCreated,
					usr.DateLastLogin == null ? DateTime.MinValue : (DateTime)usr.DateLastLogin,
					usr.DateLastActivity == null ? DateTime.MinValue : (userIsOnline) ? DateTime.Now : (DateTime)usr.DateLastActivity,
					usr.DateLastPasswordChange,
					DateTime.MinValue
				);
				return memUser;
			}
			return null;
		}

		public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
		{
			if (providerUserKey != null)
			{
				dynamic usr = Users.Find(providerUserKey);
				if (usr != null)
				{
					MembershipUser memUser = new MembershipUser(
						this.Name,
						usr.Username,
						usr.UserId,
						usr.Email,
						usr.PasswordQuestion == null ? "" : usr.PasswordQuestion,
						usr.Comment == null ? "" : usr.Comment,
						usr.IsApproved,
						false,
						usr.DateCreated,
						usr.DateLastLogin == null ? DateTime.MinValue : (DateTime)usr.DateLastLogin,
						usr.DateLastActivity == null ? DateTime.MinValue : (userIsOnline) ? DateTime.Now : (DateTime)usr.DateLastActivity,
						usr.DateLastPasswordChange,
						DateTime.MinValue
					);
					return memUser;
				}
			}
			return null;
		}

		public override string GetUserNameByEmail(string email)
		{
			if (string.IsNullOrEmpty(email) || string.IsNullOrWhiteSpace(email))
				throw new ArgumentNullException("email", "Email cannot be null or empty");

			if (!Regex.IsMatch(email, this.EmailRegularExpression))
				return "";

			dynamic list = Users.SqlQuery(q("SELECT * FROM $Users WHERE Email = '{0}'", email));

			foreach (dynamic user in list)
			{
				return user.Username;
			}

			return "";
		}

		#endregion

		#region Private Methods...

		private void HashPassword(string Password, out byte[] passwordSalt, out byte[] passwordHash)
		{
			if (Password == null) throw new ArgumentNullException("Password");
			if (string.IsNullOrWhiteSpace(Password) || string.IsNullOrEmpty(Password)) throw new ArgumentException("Value cannot be empty or null", "Password");

			using (var hmac = new System.Security.Cryptography.HMACSHA512())
			{
				passwordSalt = hmac.Key;
				passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
			}
		}

		private bool VerifyPassword(string Password, byte[] storedSalt, byte[] storedHash)
		{
			if (Password == null) throw new ArgumentNullException("Password");
			if (string.IsNullOrWhiteSpace(Password) || string.IsNullOrEmpty(Password)) throw new ArgumentException("Value cannot be empty or null", "Password");
			if (storedSalt.Length != 128) throw new ArgumentException("Invalid salt size (64 bytes expected)", "passwordSalt");
			if (storedHash.Length != 64) throw new ArgumentException("Invalid hash size (128 bytes expected)", "passwordHash");

			using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
			{
				var computed = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
				return computed.SequenceEqual(storedHash);
			}
		}

		private MembershipUserCollection FindUsers(string Where, string Match, int pageIndex, int pageSize, out int totalRecords)
		{
			pageIndex = (pageIndex == 1) ? 0 : pageIndex;

			string baseQuery = "SELECT * FROM $Users";

			MembershipUserCollection muc = new MembershipUserCollection();

			dynamic foundUsers = null;

			List<dynamic> list = new List<dynamic>();

			if (!string.IsNullOrEmpty(Where) && !string.IsNullOrEmpty(Match))
			{
				foundUsers = Users.SqlQuery(q(baseQuery + " WHERE " + Where, Match));
			}
			else
			{
				foundUsers = Users.SqlQuery(q(baseQuery));
			}

			foreach (dynamic usr in foundUsers)
			{
				list.Add(usr);
			}

			totalRecords = list.Count;

			list = list.OrderBy(x => x.Username).Skip(pageIndex * pageSize).Take(pageSize).ToList();

			list.ForEach(usr =>
			{
				muc.Add(new MembershipUser(
					this.Name,
					usr.Username,
					usr.UserId,
					usr.Email,
					usr.PasswordQuestion,
					usr.Comment == null ? "" : usr.Comment,
					usr.IsApproved,
					false,
					usr.DateCreated,
					usr.DateLastLogin == null ? DateTime.MinValue : (DateTime)usr.DateLastLogin,
					usr.DateLastActivity == null ? DateTime.MinValue : (DateTime)usr.DateLastActivity,
					usr.DateLastPasswordChange,
					DateTime.MinValue
				));
			});

			return muc;
		}

		private dynamic SetPassword(dynamic user, string password)
		{
			if (user != null)
			{
				try
				{
					byte[] passwordSalt, passwordHash;
					this.HashPassword(password, out passwordSalt, out passwordHash);
					user.PasswordHash = passwordHash;
					user.PasswordSalt = passwordSalt;
				}
				catch (Exception)
				{
					return null;
				}
				return user;
			}
			return null;
		}

		private string q(string Query, params object[] paramerters)
		{
			return string.Format(Query.Replace("$Users", this.UserTableName).Replace("$Roles", this.RoleTableName), paramerters);
		}

		#endregion

		#region Not Implemented...

		//Function will never be implemented, security risk...
		public override string GetPassword(string username, string answer)
		{
			throw new NotImplementedException();
		}

		public override bool UnlockUser(string userName)
		{
			throw new NotImplementedException();
		}

		public override int MaxInvalidPasswordAttempts
		{
			get { throw new NotImplementedException(); }
		}

		public override bool EnablePasswordRetrieval
		{
			get { throw new NotImplementedException(); }
		}

		public override int PasswordAttemptWindow
		{
			get { throw new NotImplementedException(); }
		}

		public override MembershipPasswordFormat PasswordFormat
		{
			get { throw new NotImplementedException(); }
		}

		#endregion
	}
}
