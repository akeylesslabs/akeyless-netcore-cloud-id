namespace akeyless.Cloudid;

using Newtonsoft.Json;


public class AzureCloudIdProvider : ICloudIdProvider
{
    private class TokenResult {

        [JsonProperty("access_token")]
        public string? AccessToken {get; set;}
    }

    public async Task<string> GetCloudIdAsync()
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.Add("Metadata", "true");

        var response = await client.GetAsync("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/");
        response.EnsureSuccessStatusCode();

        string responseBody = response.Content.ReadAsStringAsync().Result;

        var tokenObj = JsonConvert.DeserializeObject<TokenResult>(responseBody);

        if (tokenObj != null && !string.IsNullOrEmpty(tokenObj.AccessToken)) {
            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(tokenObj.AccessToken));
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
