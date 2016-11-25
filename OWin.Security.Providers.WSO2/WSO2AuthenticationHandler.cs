using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OWin.Security.Providers.WSO2
{
    internal class WSO2AuthenticationHandler : AuthenticationHandler<WSO2AuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private const string AuthorizeEndpoint = "oauth2/authorize";
        private const string TokenEndpoint = "oauth2/token";

        private const string TokenRevocationEndpoint = "oauth2/revoke";

        private const string UserInfoEndpoint = "oauth2/userinfo";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WSO2AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
				_httpClient.DefaultRequestHeaders.Remove("Authorization");

				string code = null;
				string state = null;

				var query = Request.Query;
				var values = query.GetValues("code");
				if (values != null && values.Count == 1)
				{
					code = values[0];
				}
				values = query.GetValues("state");
				if (values != null && values.Count == 1)
				{
					state = values[0];
				}

				properties = Options.StateDataFormat.Unprotect(state);
				if (properties == null)
				{
					return null;
				}               
				
				// OAuth2 10.12 CSRF
				if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // Check for error
                if (Request.Query.Get("error") != null)
                    return new AuthenticationTicket(null, properties);

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

				// Request the token
                var tokenResponse =
                    await _httpClient.PostAsync(Options.BaseUrl + TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;

				// Get the WSO2 user
				_httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                var graphResponse = await _httpClient.GetAsync(
					Options.BaseUrl + UserInfoEndpoint + "?schema=openid");
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                var user = JObject.Parse(text);

                var context = new WSO2AuthenticatedContext(Context, user, accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }

				context.Identity.AddClaim(new Claim(WSO2ClaimTypes.ClaimOAuthToken, accessToken, XmlSchemaString, Options.AuthenticationType));

				context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);        
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);

            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            var redirectUri =
                baseUri +
                Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            // hard code for now.
            var scope = "openid email profile";

            // allow scopes to be specified via the authentication properties for this request, when specified they will already be comma separated
            if (properties.Dictionary.ContainsKey("scope"))
            {
                scope = properties.Dictionary["scope"];
            }
                
            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                Options.BaseUrl +
                AuthorizeEndpoint +
                "?response_type=code" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&scope=" + Uri.EscapeDataString(scope) +
                "&state=" + Uri.EscapeDataString(state);


            var redirectContext = new WSO2ApplyRedirectContext(
                Context, Options,
                properties, authorizationEndpoint);
            Options.Provider.ApplyRedirect(redirectContext);

            return Task.FromResult<object>(null);
        }
    }
}
