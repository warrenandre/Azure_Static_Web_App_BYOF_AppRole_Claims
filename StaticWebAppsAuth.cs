using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

public static class StaticWebAppsAuth
{
    private class ClientPrincipal
    {
        public string IdentityProvider { get; set; }
        public string UserId { get; set; }
        public string UserDetails { get; set; }
        public IEnumerable<string> UserRoles { get; set; }
    }

    public static async Task<ClaimsPrincipal> Parse(HttpRequest req, ILogger log)
    {
        var principal = new ClientPrincipal();

        if (req.Headers.TryGetValue("x-ms-client-principal", out var header))
        {
            var data = header[0];
            var decoded = Convert.FromBase64String(data);
            var json = Encoding.UTF8.GetString(decoded);
            log.LogInformation(json);
            principal = JsonSerializer.Deserialize<ClientPrincipal>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        principal.UserRoles = principal.UserRoles?.Except(new string[] { "anonymous" }, StringComparer.CurrentCultureIgnoreCase);

        if (!principal.UserRoles?.Any() ?? true)
        {
            return new ClaimsPrincipal();
        }

        var identity = new ClaimsIdentity(principal.IdentityProvider);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, principal.UserId));
        identity.AddClaim(new Claim(ClaimTypes.Name, principal.UserDetails));
        identity.AddClaims(principal.UserRoles.Select(r => new Claim(ClaimTypes.Role, r)));
        await InjectAppRoleAssignments(req,log,identity);
        return new ClaimsPrincipal(identity);
    }

    public static async Task InjectAppRoleAssignments(HttpRequest req, ILogger log,ClaimsIdentity identity){
        GraphServiceClient graphClient = GetUserMicrosoftGraph.GetAuthenticatedGraphClient();
            log.LogInformation($"user: {req.HttpContext.User.Identity.Name}");
            var userRoleAssignments = await graphClient.Users[req.HttpContext.User.Identity.Name].AppRoleAssignments.Request()
            .Select(e => new
            {
                e.AppRoleId
            }).GetAsync();
            //var graphResult = graphClient.Users[req.HttpContext.User.Identity.Name].Request().GetAsync().Result;
            var pageIterator = PageIterator<AppRoleAssignment>
    .CreatePageIterator(
        graphClient,
        userRoleAssignments,
        // Callback executed for each item in
        // the collection
        (m) =>
        {
            //log.LogInformation($"role: {m.AppRoleId}");
            identity.AddClaim(new Claim("AppRole",m.AppRoleId.ToString()));
            return true;
        },
        // Used to configure subsequent page
        // requests
        (req) =>
        {
            // Re-add the header to subsequent requests
            req.Header("Prefer", "outlook.body-content-type=\"text\"");
            return req;
        });

            await pageIterator.IterateAsync();
    }
}

public static class GetUserMicrosoftGraph
{
    private static GraphServiceClient _graphServiceClient;
    private static GraphServiceClient graphClient = GetAuthenticatedGraphClient();

    public static GraphServiceClient GetAuthenticatedGraphClient()
    {
        var authenticationProvider = CreateAuthorizationProvider();
        _graphServiceClient = new GraphServiceClient(authenticationProvider);
        return _graphServiceClient;
    }

    private static IAuthenticationProvider CreateAuthorizationProvider()
    {
        var clientId = System.Environment.GetEnvironmentVariable("AzureADAppClientId", EnvironmentVariableTarget.Process);
        var clientSecret = System.Environment.GetEnvironmentVariable("AzureADAppClientSecret", EnvironmentVariableTarget.Process);
        var redirectUri = System.Environment.GetEnvironmentVariable("AzureADAppRedirectUri", EnvironmentVariableTarget.Process);
        var tenantId = System.Environment.GetEnvironmentVariable("AzureADAppTenantId", EnvironmentVariableTarget.Process);
        var authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";

        //this specific scope means that application will default to what is defined in the application registration rather than using dynamic scopes
        List<string> scopes = new List<string>();
        scopes.Add("https://graph.microsoft.com/.default");

        var cca = ConfidentialClientApplicationBuilder.Create(clientId)
                                          .WithAuthority(authority)
                                          .WithRedirectUri(redirectUri)
                                          .WithClientSecret(clientSecret)
                                          .Build();

        return new MsalAuthenticationProvider(cca, scopes.ToArray()); ;
    }
}

public class MsalAuthenticationProvider: IAuthenticationProvider
{
    private IConfidentialClientApplication _clientApplication;
    private string[] _scopes;

    public MsalAuthenticationProvider(IConfidentialClientApplication clientApplication, string[] scopes)
    {
        _clientApplication = clientApplication;
        _scopes = scopes;
    }

    /// <summary>
    /// Update HttpRequestMessage with credentials
    /// </summary>
    public async Task AuthenticateRequestAsync(HttpRequestMessage request)
    {
        var token = await GetTokenAsync();
        
        request.Headers.Authorization = new AuthenticationHeaderValue("bearer", token);
    }

    /// <summary>
    /// Acquire Token 
    /// </summary>
    public async Task<string> GetTokenAsync()
    {
        AuthenticationResult authResult = null;
        authResult = await _clientApplication.AcquireTokenForClient(_scopes)
                            .ExecuteAsync();
        return authResult.AccessToken;
    }
}