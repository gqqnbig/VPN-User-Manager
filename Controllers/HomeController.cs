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

namespace VPN.Controllers
{
    public class HomeController : AsyncController
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> ChangePassword(string userName, string password, string newPassword)
        {

            try
            {
                string gRecaptchaResponse = Request.Form["g-recaptcha-response"];


                UriBuilder uriBuilder = new UriBuilder("https://www.google.com/recaptcha/api/siteverify");
                var query = HttpUtility.ParseQueryString(uriBuilder.Query);
                query["secret"] = System.Configuration.ConfigurationManager.AppSettings["GoogleReCAPTCHASecretKey"];
                query["response"] = gRecaptchaResponse;
                uriBuilder.Query = query.ToString();

                WebRequest webRequest = WebRequest.CreateHttp(uriBuilder.ToString());
                webRequest.Method = "POST";
                webRequest.ContentLength = 0;
                var response = await webRequest.GetResponseAsync();
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var jsonString = sr.ReadToEnd();
                    var json = JObject.Parse(jsonString);
                    if (Convert.ToBoolean(json["success"]) == false)
                    {
                        throw new UnauthorizedAccessException("CAPTCHA validation failed. \n" + jsonString);
                    }
                }




                using (var context = new PrincipalContext(ContextType.Machine))
                using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName))
                {
                    user.ChangePassword(password, newPassword);
                }

                ViewBag.PasswordMessage = "Password is changed.";
            }
            catch (NullReferenceException)
            {
                ViewBag.PasswordMessage = "User is not found.";
            }
            catch (UnauthorizedAccessException e)
            {
                EventLog myLog = new EventLog();
                myLog.Source = "VPN User Manager";

                // Write an informational entry to the event log.    
                myLog.WriteEntry("Error in validating user input: " + e.Message, EventLogEntryType.Warning);

                ViewBag.PasswordMessage = "CAPTCHA validation failed.";
            }
            catch (Exception e)
            {
                ViewBag.PasswordMessage = e.Message;
            }


            return View("Index");
        }
    }
}