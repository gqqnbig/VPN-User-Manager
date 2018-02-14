using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Web;
using Microsoft.Owin.Security;


namespace VPN
{
    public class AdAuthenticationService
    {
        public class AuthenticationResult
        {
            public string ErrorMessage { get; } //没有set，这个属性是只读属性。跟只读字段一样，这个属性只能在构造函数中被赋值。
            public bool IsSuccess => string.IsNullOrEmpty(ErrorMessage);


            public AuthenticationResult(string errorMessage = null)
            {
                
                ErrorMessage = errorMessage;
            }

        }


        private readonly IAuthenticationManager authenticationManager;

        public AdAuthenticationService(IAuthenticationManager authenticationManager)
        {
            this.authenticationManager = authenticationManager;
        }

        public AuthenticationResult SignIn(string username, string password)
        {
            ContextType authenticationType = ContextType.Machine;

            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;

            try
            {
                isAuthenticated = principalContext.ValidateCredentials(username, password, ContextOptions.Negotiate);
                if (isAuthenticated)
                {
                    userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                }
            }
            catch (Exception)
            {
                isAuthenticated = false;
                userPrincipal = null;
            }

            if (!isAuthenticated || userPrincipal == null)
            {
                return new AuthenticationResult("Username or password is not correct.");
            }

            if (userPrincipal.IsAccountLockedOut())
            {
                return new AuthenticationResult("Your account is locked.");
            }

            if (userPrincipal.Enabled.HasValue && userPrincipal.Enabled.Value == false)
            {
                return new AuthenticationResult("Your account is disabled");
            }

            ClaimsIdentity identity = CreateIdentity(userPrincipal);

            authenticationManager.SignOut(MyAuthentication.ApplicationCookie); //这说明允许多种方式进行登录。
            authenticationManager.SignIn(new AuthenticationProperties {IsPersistent = false}, identity);

            return new AuthenticationResult();
        }

        private ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        {
            ClaimsIdentity identity = new ClaimsIdentity(MyAuthentication.ApplicationCookie,
                ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim(
                "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider",
                "Active Directory"));
            identity.AddClaim(new Claim(ClaimTypes.Name, userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userPrincipal.SamAccountName));
            if (!string.IsNullOrEmpty(userPrincipal.EmailAddress))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, userPrincipal.EmailAddress));
            }


            return identity;
        }
    }

}