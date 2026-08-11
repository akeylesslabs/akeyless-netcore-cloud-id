using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;
using akeyless.Cloudid;

namespace AkeylessCloudId.Tests
{
    // Offline tests for the AWS SigV4 STS GetCallerIdentity token builder.
    // AwsCloudIdProvider.SignRequest is fully deterministic given the supplied
    // credentials and does not touch the network, so we can drive it with fake
    // static credentials and inspect the produced cloud-id token.
    public class AwsCloudIdProviderTests
    {
        // Well-known AWS documentation example credentials (not real / not usable).
        private const string FakeAccessKey = "AKIAIOSFODNN7EXAMPLE";
        private const string FakeSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string FakeSessionToken = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN1234567890";

        // Decoded representation of the two-layer base64/JSON cloud-id token.
        private sealed class DecodedToken
        {
            public string Method;
            public string Url;                  // decoded from sts_request_url
            public string Body;                 // decoded from sts_request_body
            public Dictionary<string, string> Headers; // first value of each header
        }

        private static string Base64Decode(string value)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }

        private static DecodedToken Decode(string cloudId)
        {
            // Outer layer: base64 -> JSON object of awsData.
            var awsDumpJson = Base64Decode(cloudId);
            using var awsDoc = JsonDocument.Parse(awsDumpJson);
            var root = awsDoc.RootElement;

            var result = new DecodedToken
            {
                Method = root.GetProperty("sts_request_method").GetString(),
                Url = Base64Decode(root.GetProperty("sts_request_url").GetString()),
                Body = Base64Decode(root.GetProperty("sts_request_body").GetString()),
                Headers = new Dictionary<string, string>(StringComparer.Ordinal),
            };

            // Inner layer: sts_request_headers is base64 -> JSON object whose values
            // are string arrays (each header maps to string[]).
            var headersJson = Base64Decode(root.GetProperty("sts_request_headers").GetString());
            using var headersDoc = JsonDocument.Parse(headersJson);
            foreach (var prop in headersDoc.RootElement.EnumerateObject())
            {
                Assert.Equal(JsonValueKind.Array, prop.Value.ValueKind);
                var first = prop.Value[0].GetString();
                result.Headers[prop.Name] = first;
            }

            return result;
        }

        [Fact]
        public void SignRequest_ReturnsStsGetCallerIdentityRequest()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);
            var decoded = Decode(cloudId);

            Assert.Equal("POST", decoded.Method);
            Assert.Equal("https://sts.amazonaws.com/", decoded.Url);
            Assert.Equal("Action=GetCallerIdentity&Version=2011-06-15", decoded.Body);
        }

        [Fact]
        public void SignRequest_CarriesSigV4AuthorizationHeader()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);
            var decoded = Decode(cloudId);

            Assert.True(decoded.Headers.ContainsKey("Authorization"));
            var auth = decoded.Headers["Authorization"];

            Assert.StartsWith("AWS4-HMAC-SHA256", auth);
            Assert.Contains("Credential=" + FakeAccessKey, auth);
            Assert.Contains("/us-east-1/sts/aws4_request", auth);
            Assert.Contains("SignedHeaders=", auth);
            Assert.Contains("Signature=", auth);
        }

        [Fact]
        public void SignRequest_IncludesXAmzDateHeader()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);
            var decoded = Decode(cloudId);

            Assert.True(decoded.Headers.ContainsKey("X-Amz-Date"));
            // Format: yyyyMMddTHHmmssZ
            Assert.Matches(new Regex(@"^\d{8}T\d{6}Z$"), decoded.Headers["X-Amz-Date"]);
        }

        [Fact]
        public void SignRequest_IncludesStandardHostAndContentTypeHeaders()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);
            var decoded = Decode(cloudId);

            Assert.Equal("sts.amazonaws.com", decoded.Headers["Host"]);
            Assert.Contains("application/x-www-form-urlencoded", decoded.Headers["Content-Type"]);
            Assert.True(decoded.Headers.ContainsKey("Content-Length"));
        }

        [Fact]
        public void SignRequest_WithSessionToken_IncludesSecurityTokenHeaderAndSignsIt()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);
            var decoded = Decode(cloudId);

            Assert.True(decoded.Headers.ContainsKey("X-Amz-Security-Token"));
            Assert.Equal(FakeSessionToken, decoded.Headers["X-Amz-Security-Token"]);

            // When a session token is present it must be part of the signed headers.
            Assert.Contains("x-amz-security-token", decoded.Headers["Authorization"]);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SignRequest_WithoutSessionToken_OmitsSecurityTokenHeader(string sessionToken)
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, sessionToken);
            var decoded = Decode(cloudId);

            Assert.False(decoded.Headers.ContainsKey("X-Amz-Security-Token"));
            // And it must not be listed among the signed headers.
            Assert.DoesNotContain("x-amz-security-token", decoded.Headers["Authorization"]);
        }

        [Fact]
        public void SignRequest_ProducesValidBase64Token()
        {
            var provider = new AwsCloudIdProvider();

            var cloudId = provider.SignRequest(FakeAccessKey, FakeSecretKey, FakeSessionToken);

            Assert.False(string.IsNullOrEmpty(cloudId));
            // Must round-trip as base64 without throwing.
            var raw = Convert.FromBase64String(cloudId);
            Assert.NotEmpty(raw);
        }
    }
}
