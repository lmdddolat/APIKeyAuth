using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace APIKeyAuth.Filters
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class ,AllowMultiple =true)]
    public class ApiKeyAttribute : Attribute, IAuthorizationFilter
    {
        private const string API_KEY_HEADER_NAME = "X-API-Key";
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var submittedApiKey = GetSubmittedApiKey(context.HttpContext);
            var apiKey = GetApiKey(context.HttpContext);
            if (!IsApiKeyValid(apiKey, submittedApiKey))
            {
                context.Result = new UnauthorizedResult();
            }
        }

        private bool IsApiKeyValid(string apiKey, string submittedApiKey)
        {
            if (string.IsNullOrEmpty(submittedApiKey)) return false;

            var apiKeySpan = MemoryMarshal.Cast<char, byte>(apiKey.AsSpan());

            var submittedApiKeySpan = MemoryMarshal.Cast<char, byte>(submittedApiKey.AsSpan());

            return CryptographicOperations.FixedTimeEquals(apiKeySpan, submittedApiKeySpan);
        }

        private string GetApiKey(HttpContext httpContext)
        {
            var configuration=httpContext.RequestServices.GetRequiredService<IConfiguration>();
            return configuration.GetValue<string>($"ApiKey");
        }

        private string GetSubmittedApiKey(HttpContext httpContext)
        {
            return httpContext.Request.Headers[API_KEY_HEADER_NAME];
        }
    }
}
