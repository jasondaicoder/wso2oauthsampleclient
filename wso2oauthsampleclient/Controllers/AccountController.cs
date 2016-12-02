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
	public class AccountController : Controller
	{
		public async Task<ActionResult> ExternalLogin()
		{
			var ctx = Request.GetOwinContext();
			ctx.Authentication.Challenge(new AuthenticationProperties
			{
				RedirectUri = Url.Action("ExternalLoginCallback", "Account")
			}, 
			"WSO2");
			return new HttpUnauthorizedResult();
		}


		public async Task<ActionResult> ExternalLoginCallback()
		{
			ExternalLoginInfo loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
			if (loginInfo == null)
			{
				return RedirectToAction("Login");
			}

			await SignInAsync(loginInfo, isPersistent: false);
			return RedirectToLocal("/");
		}

		public ActionResult Logout()
		{
			AuthenticationManager.SignOut();
			
			return RedirectToLocal("/");
		}

		private IAuthenticationManager AuthenticationManager
		{
			get
			{
				return HttpContext.GetOwinContext().Authentication;
			}
		}

		private async Task SignInAsync(ExternalLoginInfo loginInfo, bool isPersistent)
		{
			AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
			var identity = new ClaimsIdentity(loginInfo.ExternalIdentity.Claims, DefaultAuthenticationTypes.ApplicationCookie);
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
