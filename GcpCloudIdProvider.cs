using Google.Apis.Auth.OAuth2;
using System.Threading.Tasks;

namespace akeyless.Cloudid {

public class GcpCloudIdProvider : ICloudIdProvider
{
    public async Task<string> GetCloudIdAsync() {
        var creds = await GoogleCredential.GetApplicationDefaultAsync();
        
        var options = OidcTokenOptions.FromTargetAudience("akeyless.io");

        var oidcToken = await creds.GetOidcTokenAsync(options);

        var token = await oidcToken.GetAccessTokenAsync();

        return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(token));
    }

    public string GetCloudId()
    {
        string token = "";
        var cont = GetCloudIdAsync().ContinueWith(cloudIdTaskRes =>
        {
            token = cloudIdTaskRes.Result;
        });

        cont.Wait();

        return token;
    }
}
}