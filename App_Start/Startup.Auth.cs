using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

namespace VPN
{
    public static class MyAuthentication
    {
        public const String ApplicationCookie = "MyProjectAuthenticationType";
    }

    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = MyAuthentication.ApplicationCookie, //AuthenticationType好像表示一个自定义的验证方案
                LoginPath = new PathString("/"),
                Provider = new CookieAuthenticationProvider(),
                CookieName = "MyCookieName",
                CookieHttpOnly = true,
                ExpireTimeSpan = TimeSpan.FromHours(1)
            });
        }
    }
}