using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Holyprin.Web.Security.MVC3.Entities;
using Holyprin.Web.Security.MVC3.MembershipCode;
using System.Web.Security;

namespace Holyprin.Web.Security.MVC3.Controllers
{ 
    public class UserController : Controller
    {
        private MyBaseContext db = new MyBaseContext();

        //
        // GET: /User/

        public ViewResult Index()
        {
            return View(db.Users.ToList());
        }

        //
        // GET: /User/Details/5

        public ViewResult Details(Guid id)
        {
            User user = db.Users.Find(id);
            return View(user);
        }

        //
        // GET: /User/Create

		[Authorize(Roles = "Administrator")]
        public ActionResult Create()
        {
            return View();
        } 

        //
        // POST: /User/Create

        [HttpPost]
		[Authorize(Roles = "Administrator")]
        public ActionResult Create(User user)
        {
            if (ModelState.IsValid)
            {
                //user.UserId = Guid.NewGuid();
                db.Users.Add(user);
                db.SaveChanges();
                return RedirectToAction("Index");  
            }

            return View(user);
        }
        
        //
        // GET: /User/Edit/5
		[Authorize(Roles = "Administrator")]
        public ActionResult Edit(Guid id)
        {
            User user = db.Users.Find(id);
            return View(user);
        }

        //
        // POST: /User/Edit/5

        [HttpPost]
		[Authorize(Roles = "Administrator")]
        public ActionResult Edit(User user)
        {
            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(user);
        }

        //
        // GET: /User/Delete/5
		[Authorize(Roles = "Administrator")]
        public ActionResult Delete(Guid id)
        {
            User user = db.Users.Find(id);
            return View(user);
        }

        //
        // POST: /User/Delete/5

        [HttpPost, ActionName("Delete")]
		[Authorize(Roles = "Administrator")]
        public ActionResult DeleteConfirmed(Guid id)
        {            
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

		//
		// GET: /User/AddRole/Id
		[Authorize(Roles = "Administrator")]
		public ActionResult AddRole(Guid id)
		{
			User user = db.Users.FirstOrDefault(u => u.UserId == id);
			IEnumerable<Role> _roles = db.Roles.ToList();
			var test = Roles.GetRolesForUser();
			var temp = Roles.GetUsersInRole("Administrator");
			ViewBag.PossibleRoles = _roles;
			return View(user);
		}

		//
		// Post: /User/AddRole/Id
		[HttpPost, ActionName("AddRole")]
		[Authorize(Roles = "Administrator")]
		public ActionResult AddRole(Guid id, Guid roleId)
		{
			User user = db.Users.FirstOrDefault(u => u.UserId == id);
			Role role = db.Roles.FirstOrDefault(r => r.RoleId == roleId);

			user.Roles.Add(role);

			db.SaveChanges();

			ViewBag.PossibleRoles = db.Roles.ToList();

			return View(user);
		}

		[HttpGet, ActionName("RemoveRole")]
		[Authorize(Roles = "Administrator")]
		public RedirectToRouteResult RemoveRole(Guid id, Guid roleId)
		{
			User user = db.Users.FirstOrDefault(u => u.UserId == id);
			Role role = db.Roles.FirstOrDefault(r => r.RoleId == roleId);

			user.Roles.Remove(role);

			db.SaveChanges();

			return RedirectToAction("AddRole", new { id = user.UserId });
		}

        protected override void Dispose(bool disposing)
        {
            db.Dispose();
            base.Dispose(disposing);
        }
    }
}