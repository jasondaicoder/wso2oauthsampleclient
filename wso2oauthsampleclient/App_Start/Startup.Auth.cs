using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.WSO2;
using System.Configuration;
using System.Threading.Tasks;
using System.Security.Claims;

namespace wso2oauthsampleclient
{
    public partial class Startup
	{
		public void ConfigureOAuth(IAppBuilder app)
		{
			app.UseCookieAuthentication(new CookieAuthenticationOptions()
			{
				AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
				LoginPath = new PathString("/Account/ExternalLogin"),
			});

			app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

			app.UseWSO2Authentication(new WSO2AuthenticationOptions()
			{
				BaseUrl = ConfigurationManager.AppSettings["OAuthServer"],
				ClientId = ConfigurationManager.AppSettings["clientId"],
				ClientSecret = ConfigurationManager.AppSettings["clientSecret"],
				Provider = new WSO2AuthenticationProvider()
				{
					OnAuthenticated = context => 
					{
						context.Identity.AddClaim(new Claim(Constants.AccessToken, context.AccessToken));
						return Task.FromResult(true);
					}
				}
			});
		}
	}
}