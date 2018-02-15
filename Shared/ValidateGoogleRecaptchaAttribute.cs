using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using Newtonsoft.Json.Linq;

namespace VPN
{
    public class ValidateGoogleRecaptchaAttribute : FilterAttribute,
        IAuthorizationFilter
    {

        
        public void OnAuthorization(AuthorizationContext filterContext)
        {
            string gRecaptchaResponse = filterContext.HttpContext.Request.Form["g-recaptcha-response"];
            UriBuilder uriBuilder = new UriBuilder("https://www.google.com/recaptcha/api/siteverify");
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            query["secret"] = System.Configuration.ConfigurationManager.AppSettings["GoogleReCAPTCHASecretKey"];
            query["response"] = gRecaptchaResponse ?? throw new UnauthorizedAccessException("reCAPTCHA token is missing.");
            uriBuilder.Query = query.ToString();

            WebRequest webRequest = WebRequest.CreateHttp(uriBuilder.ToString());
            webRequest.Method = "POST";
            webRequest.ContentLength = 0;
            var response = webRequest.GetResponse();
            using (var sr = new StreamReader(response.GetResponseStream()))
            {
                var jsonString = sr.ReadToEnd();
                var json = JObject.Parse(jsonString);
                if (Convert.ToBoolean(json["success"]) == false)
                {
                    throw new UnauthorizedAccessException("reCAPTCHA validation failed. \n" + jsonString);
                }
            }

        }
    }
}