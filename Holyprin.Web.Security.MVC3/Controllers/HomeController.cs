using System.Linq;
using System.Web.Mvc;
using Holyprin.Web.Security.MVC3.MembershipCode;
using System.Web.Security;

namespace Holyprin.Web.Security.MVC3.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
			var con = new MyBaseContext();

            ViewBag.Message = "Welcome to ASP.NET MVC!";
			ViewBag.UsersOnline = Membership.GetNumberOfUsersOnline();

			ViewBag.userNameByEmail = Membership.GetUserNameByEmail("demo@gmail.com");
			ViewBag.usersWithEmail = Membership.FindUsersByEmail("demo@gmail.com");
			ViewBag.usersWithUsername = Membership.FindUsersByName("Demo");
			ViewBag.allUsers = Membership.GetAllUsers();
			ViewBag.userByUsername = Membership.GetUser("Demo");
			ViewBag.userByKey = Membership.GetUser(ViewBag.userByUsername.ProviderUserKey);
			ViewBag.validated = Membership.ValidateUser("Demo", "demo1234");
			ViewBag.usersInAdministrator = Roles.GetUsersInRole("Administrator");

			Roles.AddUsersToRoles(new string[] { "User1", "User2", "User3" }, new string[] { "Role1", "Role2", "Role3" });

            return View(con.Roles.ToList());
        }

        public ActionResult About()
        {
            return View();
        }
    }
}
