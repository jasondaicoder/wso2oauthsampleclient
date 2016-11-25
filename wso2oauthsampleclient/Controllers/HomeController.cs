using OWin.Security.Providers.WSO2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace wso2oauthsampleclient.Controllers
{
	[Authorize]
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            return View(ClaimsPrincipal.Current.Claims);
        }

		public async Task<ActionResult> WebApi()
		{
			HttpClient httpClient = new HttpClient();

			httpClient.DefaultRequestHeaders.Authorization =
				new System.Net.Http.Headers.AuthenticationHeaderValue(
					"Bearer",
					ClaimsPrincipal.Current.Claims.FirstOrDefault(claim => claim.Type.Equals(WSO2ClaimTypes.ClaimOAuthToken)).Value);

			var response = await httpClient.GetAsync("http://localhost:8090/wso2oauthsample/api/user/hello");

			response.EnsureSuccessStatusCode();

			var text = await response.Content.ReadAsStringAsync();

			ViewBag.Text = text;
			return View();
		}
    }
}