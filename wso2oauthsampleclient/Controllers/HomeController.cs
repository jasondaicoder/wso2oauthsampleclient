using System.Configuration;
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
					Request.GetOwinContext().Request.Cookies.FirstOrDefault(c => c.Key.Equals(Constants.AccessToken)).Value);

			var response = await httpClient.GetAsync(ConfigurationManager.AppSettings["apiBaseUrl"] + "wso2oauthsample/api/user/hello");

			response.EnsureSuccessStatusCode();

			var text = await response.Content.ReadAsStringAsync();

			ViewBag.Text = text;
			return View();
		}
    }
}