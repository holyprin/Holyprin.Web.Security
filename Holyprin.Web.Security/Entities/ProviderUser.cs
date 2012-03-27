using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Holyprin.Web.Security
{
	public class ProviderUser : BaseUser<ProviderRole, Guid>
	{
		[Key]
		public override Guid UserId { get; set; }
	}

}
