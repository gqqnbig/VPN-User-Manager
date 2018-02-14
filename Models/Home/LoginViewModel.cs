using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace VPN.Home
{
    public class LoginViewModel
    {
        [Required, AllowHtml]
		[RegularExpression(@"([\d\w]+\\)?[\d\w]+", ErrorMessage = "/ is invalid character. If you want to enter domain, use \\.")]
        public string Username { get; set; }

        [Required]
        [AllowHtml]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}