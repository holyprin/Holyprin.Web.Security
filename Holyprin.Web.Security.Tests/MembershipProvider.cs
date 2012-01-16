using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Web.Security;
using System.Collections.Specialized;
using Holyprin.Web.Security;
using System.Data.Entity;

namespace Holyprin.Web.Security.Tests
{
	[TestClass]
	public class CoreTests
	{
		private MembershipProvider mprovider;
		//private RoleProvider rprovider;

		public CoreTests()
		{
			Database.SetInitializer<BaseContext>(new BaseDbInitializer());
			using (var ctx = new BaseContext())
			{
				ctx.Database.Initialize(true);
			}

			this.mprovider = new Holyprin.Web.Security.CFMembershipProvider();

			NameValueCollection config = new NameValueCollection();
			
			config.Add("applicationName", "/");
			config.Add("name", "CFMembershipProvider");
			config.Add("requiresQuestionAndAnswer", "false");
			config.Add("connectionStringName", "ApplicationServices");

			mprovider.Initialize(config["name"], config);
		}

		[TestMethod]
		public void CanCreateNewUser()
		{
			MembershipCreateStatus status = new MembershipCreateStatus();

			mprovider.CreateUser("Test1", "Testing1234", "holyprin@gmail.com", null, null, true, Guid.Empty, out status);

			Assert.AreEqual(MembershipCreateStatus.Success, status); 
		}

		[TestMethod]
		public void CanGetUserByUserId()
		{
			var user = mprovider.GetUser(Guid.Empty, true);
			Assert.AreEqual(user.UserName, "Test1");
		}

		[TestMethod]
		public void CanGetUserByUserName()
		{
			var user = mprovider.GetUser("Test1", true);
			Assert.AreEqual(user.ProviderUserKey, Guid.Empty);
		}

		[TestMethod]
		public void CanGetUserByUserIdViaMembership()
		{
			var user = Membership.GetUser(Guid.Empty);
			Assert.AreEqual(user.UserName, "Test1");
		}

		[TestMethod]
		public void CanGetUserByUserNameViaMembership()
		{
			var user = Membership.GetUser("Test1");
			Assert.AreEqual(user.ProviderUserKey, Guid.Empty);
		}
	}
}
