using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;

namespace Holyprin.Web.Security.Interfaces
{
	public interface IUserService
	{
		MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status);

		bool DeleteUser(string username, bool deleteAllRelatedData);

		void UpdateUser(MembershipUser user);

		bool ValidateUser(string username, string password);

		string ResetPassword(string username, string answer);

		bool ChangePassword(string username, string oldPassword, string newPassword);

		bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer);

		MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords);

		MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords);

		int GetNumberOfUsersOnline();

		MembershipUser GetUser(string username, bool userIsOnline);

		MembershipUser GetUser(object providerUserKey, bool userIsOnline);
	}
}
