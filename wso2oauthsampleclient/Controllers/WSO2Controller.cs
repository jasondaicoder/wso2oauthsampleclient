using Microsoft.AspNet.Identity;
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
    public class WSO2Controller : Controller
    {
		public async Task<ActionResult> Login(string returnUrl)
		{
			if (string.IsNullOrEmpty(returnUrl) && Request.UrlReferrer != null)
				returnUrl = Server.UrlEncode(Request.UrlReferrer.PathAndQuery);

			//callback function
			string redirectUrl = Url.Action("AuthorizationCodeCallback", "OAuth", null, Request.Url.Scheme);

			Dictionary<string, string> authorizeArgs = null;
			authorizeArgs = new Dictionary<string, string>
	{
		{"client_id", "ZHINlCtvoTTusUSicVh1uGOIR5ga"}
		,{"response_type", "code"}
		,{"scope", "default"}
		,{"redirect_uri", redirectUrl}
        // optional: state
    };

			var content = new FormUrlEncodedContent(authorizeArgs);
			var contentAsString = await content.ReadAsStringAsync();
			return Redirect("https://localhost:9443/oauth2/authorize?" + contentAsString);
		}

		public async Task<ActionResult> AuthorizationCodeCallback()
		{
			string returnUrl = "http://localhost:5001/OAuth/AuthorizationCodeCallback";

			// received authorization code from authorization server
			string[] codes = Request.Params.GetValues("code");
			var authorizationCode = "";
			if (codes.Length > 0)
				authorizationCode = codes[0];

			// exchange authorization code at authorization server for an access and refresh token
			Dictionary<string, string> post = null;
			post = new Dictionary<string, string>
	{
		{"client_id", "ZHINlCtvoTTusUSicVh1uGOIR5ga"}
		,{"client_secret", "LLi6TjUNk8bufYHYd99jailIX18a"}
		,{"grant_type", "authorization_code"}
		,{"code", authorizationCode}
		,{"redirect_uri", returnUrl}
	};

			var client = new HttpClient();
			var postContent = new FormUrlEncodedContent(post);
			var response = await client.PostAsync("https://localhost:9443/oauth2/token", postContent);
			var content = await response.Content.ReadAsStringAsync();

			// received tokens from authorization server
			var json = JObject.Parse(content);
			string accessToken = json["access_token"].ToString();
			string authorizationScheme = json["token_type"].ToString();
			string expiresIn = json["expires_in"].ToString();
			string refreshToken;
			if (json["refresh_token"] != null)
				refreshToken = json["refresh_token"].ToString();

			//SignIn with Token, SignOut and create new identity for SignIn
			Request.Headers.Add("Authorization", authorizationScheme + " " + accessToken);
			var ctx = Request.GetOwinContext();
			var authenticateResult = await ctx.Authentication.AuthenticateAsync(DefaultAuthenticationTypes.ExternalBearer);
			ctx.Authentication.SignOut(DefaultAuthenticationTypes.ExternalBearer);
			var applicationCookieIdentity = new ClaimsIdentity(authenticateResult.Identity.Claims, DefaultAuthenticationTypes.ApplicationCookie);
			ctx.Authentication.SignIn(applicationCookieIdentity);

			var ctxUser = ctx.Authentication.User;
			var user = Request.RequestContext.HttpContext.User;

			//redirect back to the view which required authentication
			string decodedUrl = "";
			if (!string.IsNullOrEmpty(returnUrl))
				decodedUrl = Server.UrlDecode(returnUrl);

			if (Url.IsLocalUrl(decodedUrl))
				return Redirect(decodedUrl);
			else
				return RedirectToAction("Index", "Home");
		}
	}
}