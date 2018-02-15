using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Web.Security;
using Microsoft.Owin.Security;

namespace VPN.Home
{
    public class HomeController : Controller
    {
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        [ActionName("Index")]
        [HttpPost]
        [ValidateGoogleRecaptcha]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {

            if (!ModelState.IsValid)
                return View("Index", model);

            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
            var authService = new AdAuthenticationService(authenticationManager);
            var authenticationResult = authService.SignIn(model.Username, model.Password);
            if (authenticationResult.IsSuccess)
            {
                if (string.IsNullOrEmpty(returnUrl))
                    return RedirectToAction("Index", "Account");
                else
                    return RedirectToLocal(returnUrl);
            }

            ModelState.AddModelError(string.Empty, authenticationResult.ErrorMessage);

            return View("Index", model);
        }

        public ActionResult LogOff()
        {
            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignOut(MyAuthentication.ApplicationCookie);

            return RedirectToAction("Index");
        }



        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

    }
}