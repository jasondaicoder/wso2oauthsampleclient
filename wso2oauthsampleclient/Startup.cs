using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using wso2oauthsampleclient;

[assembly: OwinStartup(typeof(Startup))]
namespace wso2oauthsampleclient
{
	public partial class Startup
	{
		public void Configuration(IAppBuilder app)
		{
			ConfigureOAuth(app);
			HttpConfiguration config = new HttpConfiguration();
			WebApiConfig.Register(config);
			app.UseWebApi(config);
		}
	}
}