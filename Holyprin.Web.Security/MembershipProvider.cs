using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Security;
using System.Data.Entity;
using System.Text.RegularExpressions;

using Holyprin.Web.Security.Configuration;

namespace Holyprin.Web.Security
{
	public class CFMembershipProvider : MembershipProvider
	{
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
			ApplicationName = config.GetConfigValue("applicationName", null);

			minRequiredNonAlphanumericCharacters = config.GetConfigValue("minRequiredNonAlphanumericCharacters", 0);
			minRequiredPasswordLength = config.GetConfigValue("minRequiredPasswordLength", 8);
			passwordStrengthRegularExpression = config.GetConfigValue("passwordStrengthRegularExpression", null);
			requiresUniqueEmail = config.GetConfigValue("requiresUniqueEmail", true);
			generatedNonAlpha = config.GetConfigValue("generatedNonAlpha", 6);
			generatedPassLength = config.GetConfigValue("generatedPassLength", 12);
			emailRegularExpression = config.GetConfigValue("emailRegularExpression", DEFAULT_EMAIL_REGEX);
			requiresQuestionAndAnswer = config.GetConfigValue("requiresQuestionAndAnswer", false);
			enablePasswordReset = config.GetConfigValue("enablePasswordReset", true);
			userTableName = CFMembershipSettings.UserTable ?? "Users";
			roleTableName = CFMembershipSettings.RoleTable ?? "Roles";
			allowLoginWithEmail = CFMembershipSettings.AllowLoginWithEmail;
			useEmailAsUsername = CFMembershipSettings.UseEmailAsUsername;

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

		public string EmailRegularExpression { get { return  emailRegularExpression; } }

		public bool UseEmailAsUsername { get { return useEmailAsUsername; } }

		public bool AllowLoginWithEmail { get { return allowLoginWithEmail; } }

		public string UserTableName { get { return userTableName; } }

		public string RoleTableName { get { return roleTableName; } }

		#endregion

		#region CUD Methods...

		public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			status = MembershipCreateStatus.Success;

			MembershipUser user = null;

			if (string.IsNullOrEmpty(username) || string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(password))
				throw new ArgumentNullException("password");
			if (string.IsNullOrEmpty(email) || string.IsNullOrWhiteSpace(email))
				throw new ArgumentNullException("email");

			if (RequiresQuestionAndAnswer)
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
			OnValidatingPassword(args);
			if (args.Cancel)
			{
				if (args.FailureInformation != null) throw args.FailureInformation;
				status = MembershipCreateStatus.InvalidPassword;
			}

			if (!Regex.IsMatch(email, EmailRegularExpression))
				status = MembershipCreateStatus.InvalidEmail;

			if (UseEmailAsUsername)
				username = email;

			if (RequiresUniqueEmail && GetUserNameByEmail(email).Trim().Length > 0)
				status = MembershipCreateStatus.DuplicateEmail;

			if (GetUser(username, false) != null)
				status = MembershipCreateStatus.DuplicateUserName;

			if (providerUserKey != null && GetUser(providerUserKey, false) != null)
				status = MembershipCreateStatus.DuplicateProviderUserKey;

			if (status == MembershipCreateStatus.Success)
			{
				byte[] passwordSalt, passwordHash;
				Guid guid;

				HashPassword(password, out passwordSalt, out passwordHash);

				dynamic usr = Activator.CreateInstance(CFMembershipSettings.UserType);

				if (CFMembershipSettings.ProviderKeyType == typeof(Guid) && providerUserKey != null && Guid.TryParse(providerUserKey.ToString(), out guid))
					usr.UserId = (Guid)providerUserKey;

				//If using SqlServeCE or the UserId is missing the DatabaseGenerated attribute
				//automatically generate keys via code, otherwise allow the server to generate them.
				if (CFMembershipSettings.ProviderKeyType == typeof(Guid) && providerUserKey == null)
				{
					var info = (CFMembershipSettings.UserType).GetProperty("UserId").GetCustomAttributesData()
						.SingleOrDefault(item => item.Constructor.ReflectedType.Name == "DatabaseGeneratedAttribute");

					if (info == null)
						usr.UserId = Guid.NewGuid(); 
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
					DataContext.SaveChanges();
				}
				catch (Exception)
				{
					status = MembershipCreateStatus.ProviderError;
				}

				user = GetUser(usr.UserId, false);
				
			}

			DataContext.Dispose();
			
			return user;
		}

		public override bool DeleteUser(string username, bool deleteAllRelatedData)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			if (string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"),new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();

			if (user != null)
			{
				if (deleteAllRelatedData)
				{
					user.Roles.Clear();
				}
				Users.Remove(user);
			}

			bool result = (DataContext.SaveChanges() > 0);

			DataContext.Dispose();

			return result;
		}

		public override void UpdateUser(MembershipUser user)
		{
			if (user == null)
				throw new ArgumentNullException("user");

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			dynamic usr = Users.Find(user.ProviderUserKey);

			if (usr != null)
			{
				usr.Username = user.UserName;
				usr.IsApproved = user.IsApproved;
				usr.DateLastActivity = user.LastActivityDate;
				usr.DateLastLogin = user.LastLoginDate;
				usr.DateLastPasswordChange = user.LastPasswordChangedDate;
				usr.PasswordQuestion = user.PasswordQuestion;
				usr.Email = user.Email;
				usr.Comment = user.Comment;
				usr.IsApproved = user.IsApproved;

				DataContext.SaveChanges();
			}
			DataContext.Dispose();
		}

		public override bool ValidateUser(string username, string password)
		{
			if (string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			if (string.IsNullOrWhiteSpace(password))
				throw new ArgumentNullException("password");

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			dynamic user;

			if ((AllowLoginWithEmail || UseEmailAsUsername) && RequiresUniqueEmail)
			{
				user = Regex.IsMatch(username, EmailRegularExpression) 
					? Users.SqlQuery(q("SELECT * FROM $Users WHERE Email = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault() 
					: Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();
			}
			else
			{
				user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();
			}

			bool result = false;

			if (user != null)
			{
				if (VerifyPassword(password, user.PasswordSalt, user.PasswordHash))
				{
					user.DateLastLogin = DateTime.Now;
					user.DateLastActivity = DateTime.Now;
					result = true;
				}
			}

			DataContext.SaveChanges();

			DataContext.Dispose();

			return result;
		}

		public override string ResetPassword(string username, string answer)
		{
			if (string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			string newPassword = null;

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();

			if (user != null)
			{
				if ((EnablePasswordReset && !RequiresQuestionAndAnswer) || ((answer.ToLower().Trim() == user.PasswordAnswer.ToLower().Trim())) && (RequiresQuestionAndAnswer))
				{
					newPassword = Membership.GeneratePassword(generatedPassLength, generatedNonAlpha);
					dynamic temp = SetPassword(user, newPassword);

					user.PasswordHash = temp.PasswordHash;
					user.PasswordSalt = temp.PasswordSalt;
				}
			}
			if (newPassword == null)
				throw new Exception("The new password could not be generated. Please verify the input fields are correct.");

			DataContext.SaveChanges();

			DataContext.Dispose();

			return newPassword;
		}

		public override bool ChangePassword(string username, string oldPassword, string newPassword)
		{
			if (string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			if (string.IsNullOrWhiteSpace(oldPassword))
				throw new ArgumentNullException("oldPassword");
			if (string.IsNullOrWhiteSpace(newPassword))
				throw new ArgumentNullException("newPassword");
			if (!this.CheckPasswordPolicy(newPassword))
				return false;

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			bool result = false;

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();

			if (user != null)
			{
				try
				{
					bool verifiedOld = VerifyPassword(oldPassword, user.PasswordSalt, user.PasswordHash);
					if (verifiedOld)
					{
						dynamic temp = SetPassword(user, newPassword);

						user.PasswordHash = temp.PasswordHash;
						user.PasswordSalt = temp.PasswordSalt;

						result = true;
					}
				}
				catch (Exception)
				{
					result = false;
				}
			}

			DataContext.SaveChanges();

			DataContext.Dispose();

			return result;
		}

		public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			if (string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");
			if (string.IsNullOrWhiteSpace(password))
				throw new ArgumentNullException("password");
			if (string.IsNullOrWhiteSpace(newPasswordQuestion))
				throw new ArgumentNullException("newPasswordQuestion");
			if (string.IsNullOrWhiteSpace(newPasswordAnswer))
				throw new ArgumentNullException("newPasswordAnswer");

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			bool result = false;

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username", username)).Cast<dynamic>().FirstOrDefault();

			if (user != null)
			{
				if (VerifyPassword(password, user.PasswordSalt, user.PasswordHash))
				{
					try
					{
						user.PasswordQuestion = newPasswordQuestion;
						user.PasswordAnswer = newPasswordAnswer;
						result = true;
					}
					catch (Exception)
					{
						result = false;
					}
				}
			}

			DataContext.SaveChanges();

			DataContext.Dispose();

			return result;
		}

		#endregion

		#region Select Methods...

		public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			if (string.IsNullOrWhiteSpace(emailToMatch))
				throw new ArgumentNullException("emailToMatch");

			return FindUsers("Email = @email", new System.Data.SqlClient.SqlParameter("@email",emailToMatch), pageIndex, pageSize, out totalRecords);
		}

		public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			if (string.IsNullOrWhiteSpace(usernameToMatch))
				throw new ArgumentNullException("usernameToMatch");

			return FindUsers("Username = @username", new System.Data.SqlClient.SqlParameter("@username", usernameToMatch), pageIndex, pageSize, out totalRecords);
		}

		public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
		{
			return FindUsers(null, null, pageIndex, pageSize, out totalRecords);
		}

		public override int GetNumberOfUsersOnline()
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);

			DateTime cutoff = DateTime.Now.AddMinutes(-Membership.UserIsOnlineTimeWindow);

			int count = DataContext.Database.SqlQuery(typeof(int), q("SELECT COUNT(*) FROM $Users WHERE DateLastActivity > @CutOff"), new System.Data.SqlClient.SqlParameter("@CutOff", cutoff))
				.Cast<int>().FirstOrDefault();

			return count;
		}

		public override MembershipUser GetUser(string username, bool userIsOnline)
		{
			if (string.IsNullOrEmpty(username) || string.IsNullOrWhiteSpace(username))
				throw new ArgumentNullException("username");

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			MembershipUser memUser = null;

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Username = @username"), new System.Data.SqlClient.SqlParameter("@username",username)).Cast<dynamic>().FirstOrDefault();

			if (user != null) 
			{
				memUser = new MembershipUser(
					Name,
					user.Username,
					user.UserId,
					user.Email,
					user.PasswordQuestion ?? "",
					user.Comment ?? "",
					user.IsApproved,
					false,
					user.DateCreated,
					user.DateLastLogin == null ? DateTime.MinValue : (DateTime)user.DateLastLogin,
					user.DateLastActivity == null ? DateTime.MinValue : (userIsOnline) ? DateTime.Now : (DateTime)user.DateLastActivity,
					user.DateLastPasswordChange,
					DateTime.MinValue
				);
			}

			DataContext.Dispose();

			return memUser;
		}

		public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
		{
			if (providerUserKey == null)
				throw new ArgumentNullException("providerUserKey");

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			MembershipUser memUser = null;

			dynamic usr = Users.Find(providerUserKey);

			if (usr != null)
			{
				memUser = new MembershipUser(
					Name,
					usr.Username,
					usr.UserId,
					usr.Email,
					usr.PasswordQuestion ?? "",
					usr.Comment ?? "",
					usr.IsApproved,
					false,
					usr.DateCreated,
					usr.DateLastLogin == null ? DateTime.MinValue : (DateTime)usr.DateLastLogin,
					usr.DateLastActivity == null ? DateTime.MinValue : (userIsOnline) ? DateTime.Now : (DateTime)usr.DateLastActivity,
					usr.DateLastPasswordChange,
					DateTime.MinValue
				);
			}

			DataContext.Dispose();

			return memUser;
		}

		public override string GetUserNameByEmail(string email)
		{
			if (string.IsNullOrEmpty(email) || string.IsNullOrWhiteSpace(email))
				throw new ArgumentNullException("email", "Email cannot be null or empty");

			if (!Regex.IsMatch(email, EmailRegularExpression))
				return "";

			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			dynamic user = Users.SqlQuery(q("SELECT * FROM $Users WHERE Email = @email"), new System.Data.SqlClient.SqlParameter("@email", email)).Cast<dynamic>().FirstOrDefault();

			return user != null ? user.Username : "";
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

		private MembershipUserCollection FindUsers(string Where, System.Data.SqlClient.SqlParameter Match, int pageIndex, int pageSize, out int totalRecords)
		{
			//Thread Safety
			DbContext DataContext = (DbContext)Activator.CreateInstance(CFMembershipSettings.DataContext);
			DbSet Users = DataContext.Set(CFMembershipSettings.UserType);

			pageIndex = (pageIndex == 1) ? 0 : pageIndex;

			const string baseQuery = "SELECT * FROM $Users";

			MembershipUserCollection muc = new MembershipUserCollection();

			dynamic foundUsers;

			List<dynamic> list = new List<dynamic>();

			if (!string.IsNullOrEmpty(Where) && Match != null)
			{
				foundUsers = Users.SqlQuery(q(baseQuery + " WHERE " + Where), Match);
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

			list.ForEach(usr => muc.Add(new MembershipUser(
			                            	Name,
			                            	usr.Username,
			                            	usr.UserId,
			                            	usr.Email,
			                            	usr.PasswordQuestion,
			                            	usr.Comment ?? "",
			                            	usr.IsApproved,
			                            	false,
			                            	usr.DateCreated,
			                            	usr.DateLastLogin == null ? DateTime.MinValue : (DateTime)usr.DateLastLogin,
			                            	usr.DateLastActivity == null ? DateTime.MinValue : (DateTime)usr.DateLastActivity,
			                            	usr.DateLastPasswordChange,
			                            	DateTime.MinValue
			                            	)));

			DataContext.Dispose();

			return muc;
		}

		private dynamic SetPassword(dynamic user, string password)
		{
			if (user != null)
			{
				try
				{
					byte[] passwordSalt, passwordHash;
					HashPassword(password, out passwordSalt, out passwordHash);
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

			return string.Format(Query.Replace("$Users", UserTableName).Replace("$Roles", RoleTableName), paramerters);
		}

		#endregion

		#region Not Implemented...

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
