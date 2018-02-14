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
    public class HomeController : AsyncController
    {
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        //[HttpPost]
        //[ActionName("Index")]
        //public async Task<ActionResult> ChangePassword(string userName, string password, string newPassword)
        //{
        //    string gRecaptchaResponse = Request.Form["g-recaptcha-response"];


        //    UriBuilder uriBuilder = new UriBuilder("https://www.google.com/recaptcha/api/siteverify");
        //    var query = HttpUtility.ParseQueryString(uriBuilder.Query);
        //    query["secret"] = System.Configuration.ConfigurationManager.AppSettings["GoogleReCAPTCHASecretKey"];
        //    query["response"] = gRecaptchaResponse;
        //    uriBuilder.Query = query.ToString();

        //    WebRequest webRequest = WebRequest.CreateHttp(uriBuilder.ToString());
        //    webRequest.Method = "POST";
        //    webRequest.ContentLength = 0;
        //    var response = await webRequest.GetResponseAsync();
        //    using (var sr = new StreamReader(response.GetResponseStream()))
        //    {
        //        var jsonString = sr.ReadToEnd();
        //        var json = JObject.Parse(jsonString);
        //        if (Convert.ToBoolean(json["success"]) == false)
        //        {
        //            throw new UnauthorizedAccessException("CAPTCHA validation failed. \n" + jsonString);
        //        }
        //    }



        //    if (Membership.ValidateUser(userName, password))
        //    {
        //        FormsAuthentication.SetAuthCookie(userName, true);
        //        return RedirectToAction("Index", "Account");
        //    }



        //    return View("Index");
        //}


        [HttpPost]
        [AllowAnonymous]
        public ActionResult Index(LoginViewModel model, string returnUrl)
        {

            if (!ModelState.IsValid)
                return View(model);

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

            return View(model);
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