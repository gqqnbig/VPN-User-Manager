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
		[HttpGet]
		public ViewResult Index()
        {
			var model = new IndexViewModel();

			using (var context = new PrincipalContext(ContextType.Domain,"meridianlink"))
			using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, User.Identity.Name))
			{
				model.LastLoginDate =  user.LastLogon;

			}

			var products = System.Web.HttpContext.Current.Application["Products"] as List<Product>;
			if (products != null)
				model.Products = from p in products
								 select new ProductViewModel { Name = p.Name, Quantity = p.Quantitiy };

			return View(model);
		}

		[HttpPost]
		[ActionName("Index")]
		public ActionResult AddProduct(AddProductInputModel input)
		{

			var products = System.Web.HttpContext.Current.Application["Products"] as List<Product>;
			if (products == null)
			{
				products = new List<Product>();
				System.Web.HttpContext.Current.Application["Products"] = products;
			}

			if (ModelState.IsValid)
			{
				products.Add(new Product { Id = Guid.NewGuid(), Name = input.Name, Quantitiy = input.Quantity, Owner = User.Identity.Name });
			}

			return Index();
		}

	}
}