using Azure.Core;
using Azure.Identity;
using Newtonsoft.Json;
using System.Threading.Tasks;
using System.Net.Http;
using System;

namespace akeyless.Cloudid {

public class AzureCloudIdProvider : ICloudIdProvider
{
    public async Task<string> GetCloudIdAsync()
    {
        string[] scopes = new string[] { "https://management.azure.com/.default" };

        var credential = new DefaultAzureCredential();
        
        var tokenRequestContext = new TokenRequestContext(scopes);
        var accessToken = await credential.GetTokenAsync(tokenRequestContext);
                
        if (!string.IsNullOrEmpty(accessToken.Token)) {
            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(accessToken.Token));
        } else {
            throw new Exception("Failed to get access token");
        }
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