using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace VPN.Account
{

    [Authorize(Roles = "VPN Customers")]
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
			var model = new IndexViewModel();

			using (var context = new PrincipalContext(ContextType.Domain,"meridianlink"))
			using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, User.Identity.Name))
			{
				model.LastLoginDate =  user.LastLogon;

			}

			return View(model);
        }
    }
}