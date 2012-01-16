using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Holyprin.Web.Security.MVC3.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
			var con = new BaseContext();

            ViewBag.Message = "Welcome to ASP.NET MVC!";

            return View(con.Roles.ToList());
        }

        public ActionResult About()
        {
            return View();
        }
    }
}
