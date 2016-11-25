using System.Threading.Tasks;

namespace OWin.Security.Providers.WSO2
{
	public interface IWSO2AuthenticationProvider 
	{
		Task Authenticated(WSO2AuthenticatedContext context);

		Task ReturnEndpoint(WSO2AuthenticatedContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the LinkedIn middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(WSO2ApplyRedirectContext context);		
	}
}