using System;
using System.Text;
using Xunit;
using akeyless.Cloudid;

namespace AkeylessCloudId.Tests
{
    // Credentials-gated live end-to-end tests. These actually resolve real cloud
    // credentials (AWS credential chain / Azure DefaultAzureCredential / GCP ADC)
    // and hit live endpoints, so they only run when explicitly enabled AND the
    // relevant credentials are present in the environment. Otherwise they return
    // early so CI stays green without any secrets configured.
    //
    // Enable by setting AKEYLESS_LIVE_E2E=1 together with the provider credentials.
    public class LiveE2ETests
    {
        private static bool LiveEnabled =>
            Environment.GetEnvironmentVariable("AKEYLESS_LIVE_E2E") == "1";

        private static bool HasEnv(string name) =>
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name));

        [Fact]
        public void Aws_GetCloudId_Live_ProducesDecodableToken()
        {
            if (!LiveEnabled || !HasEnv("AWS_ACCESS_KEY_ID"))
            {
                // gated: no live AWS credentials -> skip.
                return;
            }

            var provider = CloudIdProviderFactory.GetCloudIdProvider("aws_iam");
            var cloudId = provider.GetCloudId();

            Assert.False(string.IsNullOrEmpty(cloudId));
            var awsDump = Encoding.UTF8.GetString(Convert.FromBase64String(cloudId));
            Assert.Contains("sts_request_headers", awsDump);
        }

        [Fact]
        public void Azure_GetCloudId_Live_ProducesToken()
        {
            if (!LiveEnabled || !HasEnv("AZURE_CLIENT_ID"))
            {
                // gated: no live Azure credentials -> skip.
                return;
            }

            var provider = CloudIdProviderFactory.GetCloudIdProvider("azure_ad");
            var cloudId = provider.GetCloudId();

            Assert.False(string.IsNullOrEmpty(cloudId));
            // Token is base64 of the raw access token; verify it round-trips.
            Assert.NotEmpty(Convert.FromBase64String(cloudId));
        }

        [Fact]
        public void Gcp_GetCloudId_Live_ProducesToken()
        {
            if (!LiveEnabled || !HasEnv("GOOGLE_APPLICATION_CREDENTIALS"))
            {
                // gated: no live GCP credentials -> skip.
                return;
            }

            var provider = CloudIdProviderFactory.GetCloudIdProvider("gcp");
            var cloudId = provider.GetCloudId();

            Assert.False(string.IsNullOrEmpty(cloudId));
            Assert.NotEmpty(Convert.FromBase64String(cloudId));
        }
    }
}
