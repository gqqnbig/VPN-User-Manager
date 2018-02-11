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
using NetFwTypeLib;

namespace VPN.Controllers
{
    public class HomeController : AsyncController
    {
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ActionName("Index")]
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
                    using (var group = new GroupPrincipal(context, "VPN Customers"))
                    {
                        if (user.IsMemberOf(group) == false)
                        {
                            Firewall.BlockIPInFirewall(Request.UserHostAddress);
                            throw new UnauthorizedAccessException($"User {userName} doesn't belong to group VPN Customers.");
                        }
                        user.ChangePassword(password, newPassword);
                    }

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
                myLog.WriteEntry("Error in validating user: " + e.Message, EventLogEntryType.Warning);

                ViewBag.PasswordMessage = "Validation failed.";
            }
            catch (Exception e)
            {
                ViewBag.PasswordMessage = e.Message;
            }


            return View("Index");
        }


    }



    public class Firewall
    {

        public static void BlockIPInFirewall(string sourceIP)
        {
            const string ruleName = "Block Malicious IP";

            string blockRange;
            if (sourceIP.Contains("."))
            {
                blockRange = sourceIP.Substring(0, sourceIP.LastIndexOf('.')) + ".0/24";
            }
            else
            {
                blockRange= sourceIP.Substring(0, sourceIP.LastIndexOf(':')) + ":0/112";
            }



            var firewallRule = GetFirewallRule(ruleName);
            if (firewallRule == null)
            {
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                var currentProfiles = fwPolicy2.CurrentProfileTypes;

                // Let's create a new rule

                INetFwRule2 inboundRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                inboundRule.Name = ruleName;
                inboundRule.Enabled = true;
                inboundRule.Protocol = 6; // TCP
                inboundRule.RemoteAddresses = blockRange;
                inboundRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;

                inboundRule.Profiles = currentProfiles;


                fwPolicy2.Rules.Add(inboundRule);
            }
            else
            {
                firewallRule.RemoteAddresses += "," + blockRange;
            }



        }

        private static INetFwRule GetFirewallRule(string ruleName)
        {
            var fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));


            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                // Add rule to list
                //RuleList.Add(rule);
                // Console.WriteLine(rule.Name);
                if (rule.Name == ruleName)
                {
                    return rule;
                }
            }

            return null;
        }
    }
}