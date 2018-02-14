using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace VPN
{
	public class Product
	{
		public Guid Id { get; set; }

		public string Name { get; set; }

		public int Quantitiy { get; set; }

		public string Owner { get; set; }
	}
}