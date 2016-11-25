using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;

namespace wso2oauthsampleclient.Controllers
{
	public class OAuthController : Controller
	{
		public async Task<ActionResult> ExternalLogin()
		{
			var ctx = Request.GetOwinContext();
			ctx.Authentication.Challenge(new AuthenticationProperties
			{
				RedirectUri = Url.Action("ExternalLoginCallback", "OAuth")
			}, 
			"WSO2");
			return new HttpUnauthorizedResult();
		}


		public async Task<ActionResult> ExternalLoginCallback()
		{
			ExternalLoginInfo loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
			//if (loginInfo == null)
			//{
			//	return RedirectToAction("Login");
			//}

			AuthenticateResult result = await AuthenticationManager.AuthenticateAsync("WSO2");
			await SignInAsync(result, isPersistent: false);
			return RedirectToLocal("/");
		}

		private IAuthenticationManager AuthenticationManager
		{
			get
			{
				return HttpContext.GetOwinContext().Authentication;
			}
		}

		private async Task SignInAsync(AuthenticateResult loginInfo, bool isPersistent)
		{
			AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
			var identity = new ClaimsIdentity(loginInfo.Identity.Claims, DefaultAuthenticationTypes.ApplicationCookie);
			AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
		}

		private ActionResult RedirectToLocal(string returnUrl)
		{
			if (Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}
			else
			{
				return RedirectToAction("Index", "Home");
			}
		}
	}
}
