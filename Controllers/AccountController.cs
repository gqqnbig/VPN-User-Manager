using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace VPN.Controllers
{

    [Authorize]
    public class AccountController : Controller
    {
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost, ActionName("Index")]
        public ActionResult ChangePassword(string newPassword)
        {
            try
            {
                ContextType authenticationType =
                    User.Identity.Name.Contains("\\") ? ContextType.Domain : ContextType.Machine;

                PrincipalContext principalContext = new PrincipalContext(authenticationType);
                var userPrincipal = UserPrincipal.FindByIdentity(principalContext, User.Identity.Name);
                userPrincipal.SetPassword(newPassword);

                ViewData["Success"] = "Password is changed!";
            }
            catch (Exception e)
            {
                ModelState.AddModelError(string.Empty, e);
            }

            return View("Index");

        }


    }
}