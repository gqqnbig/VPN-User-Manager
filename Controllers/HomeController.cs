using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace VPN.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ChangePassword(string userName, string password, string newPassword)
        {

            using (var context = new PrincipalContext(ContextType.Machine))
            using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName))
            {
                user.ChangePassword(password, newPassword);
            }

            ViewBag.IsChangeSuccessful = true;



            return View("Index");
        }
    }
}