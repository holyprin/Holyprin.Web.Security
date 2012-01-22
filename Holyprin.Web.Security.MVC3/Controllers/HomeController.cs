using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
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

            return View(con.Roles.ToList());
        }

        public ActionResult About()
        {
            return View();
        }
    }
}
