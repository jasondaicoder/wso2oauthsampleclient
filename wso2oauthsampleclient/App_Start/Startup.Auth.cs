using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using OWin.Security.Providers.WSO2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace wso2oauthsampleclient
{
	public partial class Startup
	{
		public void ConfigureOAuth(IAppBuilder app)
		{
			app.UseCookieAuthentication(new CookieAuthenticationOptions()
			{
				AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
				LoginPath = new PathString("/OAuth/ExternalLogin"),
			});

			app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

			app.UseWSO2Authentication("https://localhost:9443/", "ZHINlCtvoTTusUSicVh1uGOIR5ga", "LLi6TjUNk8bufYHYd99jailIX18a");
		}
	}
}