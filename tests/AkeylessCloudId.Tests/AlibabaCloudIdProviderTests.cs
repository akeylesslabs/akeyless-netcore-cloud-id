using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using akeyless.Cloudid;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AkeylessCloudId.Tests
{
    public class AlibabaCloudIdProviderTests
    {
        private const string TestTimestamp = "2026-05-11T10:00:00Z";
        private const string TestNonce = "fixed-nonce";

        [Fact]
        public void DefaultRegionUsesHangzhouAndGlobalSts()
        {
            var token = Decode(Sign(""));
            Assert.Equal("POST", token.Method);
            Assert.StartsWith("https://sts.aliyuncs.com/?", token.Url);
            Assert.Equal("", token.Body);
            Assert.Equal(AlibabaCloudIdProvider.DefaultRegion, Query(token.Url)["RegionId"]);
            Assert.Equal(AlibabaCloudIdProvider.StsApiAction, Query(token.Url)["Action"]);
            Assert.Equal(AlibabaCloudIdProvider.StsApiVersion, Query(token.Url)["Version"]);
            Assert.False(string.IsNullOrEmpty(Query(token.Url)["Signature"]));
        }

        [Fact]
        public void ConfiguredRegionIsSigned()
        {
            var token = Decode(Sign("cn-beijing"));
            Assert.Equal("cn-beijing", Query(token.Url)["RegionId"]);
        }

        [Fact]
        public void IncludesSecurityToken()
        {
            var token = Decode(Sign("cn-hangzhou", "SESSION"));
            Assert.Equal("SESSION", Query(token.Url)["SecurityToken"]);
        }

        [Fact]
        public void PayloadHasCompatibleHeaders()
        {
            var token = Decode(Sign("cn-hangzhou"));
            Assert.Equal("application/x-www-form-urlencoded", (string)token.Headers["Content-Type"][0]);
            Assert.Equal(AlibabaCloudIdProvider.StsApiAction, (string)token.Headers["X-Acs-Action"][0]);
            Assert.Equal(AlibabaCloudIdProvider.StsApiVersion, (string)token.Headers["X-Acs-Version"][0]);
        }

        [Fact]
        public void ImdsV2TokenRequestUsesHardenedHeaders()
        {
            using (var request = AlibabaCloudIdProvider.CreateImdsV2TokenRequest())
            {
                Assert.Equal(HttpMethod.Put, request.Method);
                Assert.Equal(
                    AlibabaCloudIdProvider.EcsMetadataBaseUrl + AlibabaCloudIdProvider.EcsMetadataTokenPath,
                    request.RequestUri.ToString());
                Assert.True(request.Headers.TryGetValues(AlibabaCloudIdProvider.EcsMetadataTokenTtlHeader, out var values));
                Assert.Equal(AlibabaCloudIdProvider.EcsMetadataTokenTtlSeconds, Assert.Single(values));
            }
        }

        [Fact]
        public void ImdsGetRequestIncludesTokenWhenPresent()
        {
            using (var request = AlibabaCloudIdProvider.CreateImdsGetRequest(
                       AlibabaCloudIdProvider.EcsMetadataBaseUrl + AlibabaCloudIdProvider.EcsRamCredentialsPath,
                       "imds-token"))
            {
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.True(request.Headers.TryGetValues(AlibabaCloudIdProvider.EcsMetadataTokenHeader, out var values));
                Assert.Equal("imds-token", Assert.Single(values));
            }
        }

        [Fact]
        public void ImdsGetRequestOmitsTokenForV1Fallback()
        {
            using (var request = AlibabaCloudIdProvider.CreateImdsGetRequest(
                       AlibabaCloudIdProvider.EcsMetadataBaseUrl + AlibabaCloudIdProvider.EcsRamCredentialsPath,
                       null))
            {
                Assert.False(request.Headers.Contains(AlibabaCloudIdProvider.EcsMetadataTokenHeader));
            }
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData("false", false)]
        [InlineData("true", true)]
        [InlineData("TRUE", true)]
        [InlineData("1", true)]
        [InlineData("yes", true)]
        public void TruthyImdsPolicyValues(string value, bool expected)
        {
            Assert.Equal(expected, AlibabaCloudIdProvider.IsTruthyEnvValue(value));
        }

        [Fact]
        public void FirstMetadataLineUsesFirstRoleName()
        {
            Assert.Equal("AliyunECSRole", AlibabaCloudIdProvider.FirstMetadataLine("AliyunECSRole\nSecondRole\n"));
        }

        [Fact]
        public async Task EcsRamRoleUsesImdsV2Token()
        {
            using (new EnvScope(
                       ("ALIBABA_CLOUD_ACCESS_KEY_ID", null),
                       ("ALICLOUD_ACCESS_KEY", null),
                       ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", null),
                       ("ALICLOUD_SECRET_KEY", null),
                       ("ALIBABA_CLOUD_SECURITY_TOKEN", null),
                       ("ALICLOUD_SECURITY_TOKEN", null),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLED", null),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLE", null)))
            {
                var handler = new StubImdsHandler(requireToken: true);
                var cloudId = await new AlibabaCloudIdProvider(handler).GetCloudIdAsync();
                var token = Decode(cloudId);

                Assert.True(handler.TokenRequested);
                Assert.True(handler.RoleNameUsedToken);
                Assert.True(handler.CredentialsUsedToken);
                Assert.Equal("STS.AKID", Query(token.Url)["AccessKeyId"]);
                Assert.Equal("STSTOKEN", Query(token.Url)["SecurityToken"]);
            }
        }

        [Fact]
        public async Task EcsRamRoleFallsBackToImdsV1WhenTokenRequestFails()
        {
            using (new EnvScope(
                       ("ALIBABA_CLOUD_ACCESS_KEY_ID", null),
                       ("ALICLOUD_ACCESS_KEY", null),
                       ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", null),
                       ("ALICLOUD_SECRET_KEY", null),
                       ("ALIBABA_CLOUD_SECURITY_TOKEN", null),
                       ("ALICLOUD_SECURITY_TOKEN", null),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLED", null),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLE", null)))
            {
                var handler = new StubImdsHandler(requireToken: false, failTokenRequest: true);
                var cloudId = await new AlibabaCloudIdProvider(handler).GetCloudIdAsync();
                var token = Decode(cloudId);

                Assert.True(handler.TokenRequested);
                Assert.False(handler.RoleNameUsedToken);
                Assert.Equal("STS.AKID", Query(token.Url)["AccessKeyId"]);
            }
        }

        [Fact]
        public async Task EcsRamRoleDoesNotFallBackWhenImdsV1Disabled()
        {
            using (new EnvScope(
                       ("ALIBABA_CLOUD_ACCESS_KEY_ID", null),
                       ("ALICLOUD_ACCESS_KEY", null),
                       ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", null),
                       ("ALICLOUD_SECRET_KEY", null),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLED", "true"),
                       ("ALIBABA_CLOUD_IMDSV1_DISABLE", null)))
            {
                var handler = new StubImdsHandler(requireToken: false, failTokenRequest: true);
                await Assert.ThrowsAsync<HttpRequestException>(
                    () => new AlibabaCloudIdProvider(handler).GetCloudIdAsync());
            }
        }

        [Fact]
        public void GetCloudIdUsesEnvironmentCredentialsWithoutMetadata()
        {
            using (new EnvScope(
                       ("ALIBABA_CLOUD_ACCESS_KEY_ID", "ENV.AKID"),
                       ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ENVSECRET"),
                       ("ALIBABA_CLOUD_SECURITY_TOKEN", null),
                       ("ALICLOUD_ACCESS_KEY", null),
                       ("ALICLOUD_SECRET_KEY", null)))
            {
                var handler = new StubImdsHandler(requireToken: true);
                var token = Decode(new AlibabaCloudIdProvider(handler).GetCloudId());

                Assert.False(handler.TokenRequested);
                Assert.Equal("ENV.AKID", Query(token.Url)["AccessKeyId"]);
            }
        }

        [Fact]
        public void RpcStringToSignIsDeterministic()
        {
            var queryParams = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                ["AccessKeyId"] = "AKID",
                ["Action"] = AlibabaCloudIdProvider.StsApiAction,
                ["Format"] = AlibabaCloudIdProvider.StsApiFormat,
                ["RegionId"] = AlibabaCloudIdProvider.DefaultRegion,
                ["SignatureMethod"] = AlibabaCloudIdProvider.SignatureMethod,
                ["SignatureNonce"] = TestNonce,
                ["SignatureType"] = "",
                ["SignatureVersion"] = "1.0",
                ["Timestamp"] = TestTimestamp,
                ["Version"] = AlibabaCloudIdProvider.StsApiVersion,
            };

            var stringToSign = AlibabaCloudIdProvider.BuildRpcStringToSign("POST", queryParams);
            var signature = AlibabaCloudIdProvider.ShaHmac1(stringToSign, "SECRET&");

            Assert.Equal(
                "POST&%2F&AccessKeyId%3DAKID%26Action%3DGetCallerIdentity%26Format%3DJSON%26RegionId%3Dcn-hangzhou%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3Dfixed-nonce%26SignatureType%3D%26SignatureVersion%3D1.0%26Timestamp%3D2026-05-11T10%253A00%253A00Z%26Version%3D2015-04-01",
                stringToSign);
            Assert.Equal("dSCqL2sSKYDmcOcAj2Grhpar/wE=", signature);
        }

        private static string Sign(string region, string securityToken = "")
        {
            return new AlibabaCloudIdProvider().SignRequest("AKID", "SECRET", securityToken, region, TestTimestamp, TestNonce);
        }

        private static Dictionary<string, string> Query(string url)
        {
            var result = new Dictionary<string, string>();
            var raw = new Uri(url).Query;
            if (string.IsNullOrEmpty(raw) || raw.Length < 2)
            {
                return result;
            }
            foreach (var pair in raw.Substring(1).Split('&'))
            {
                var parts = pair.Split(new[] { '=' }, 2);
                var key = Uri.UnescapeDataString(parts[0].Replace("+", " "));
                var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace("+", " ")) : "";
                result[key] = value;
            }
            return result;
        }

        private static DecodedToken Decode(string cloudId)
        {
            var root = JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(cloudId)));
            return new DecodedToken
            {
                Method = (string)root["sts_request_method"],
                Url = Encoding.UTF8.GetString(Convert.FromBase64String((string)root["sts_request_url"])),
                Body = Encoding.UTF8.GetString(Convert.FromBase64String((string)root["sts_request_body"])),
                Headers = JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String((string)root["sts_request_headers"]))),
            };
        }

        private sealed class DecodedToken
        {
            public string Method { get; set; }
            public string Url { get; set; }
            public string Body { get; set; }
            public JObject Headers { get; set; }
        }

        private sealed class EnvScope : IDisposable
        {
            private readonly List<Action> _restore = new List<Action>();

            public EnvScope(params (string Key, string Value)[] assignments)
            {
                foreach (var assignment in assignments)
                {
                    var key = assignment.Key;
                    var previous = Environment.GetEnvironmentVariable(key);
                    _restore.Add(() => Environment.SetEnvironmentVariable(key, previous));
                    Environment.SetEnvironmentVariable(key, assignment.Value);
                }
            }

            public void Dispose()
            {
                for (var i = _restore.Count - 1; i >= 0; i--)
                {
                    _restore[i]();
                }
            }
        }

        private sealed class StubImdsHandler : HttpMessageHandler
        {
            private readonly bool _requireToken;
            private readonly bool _failTokenRequest;

            public StubImdsHandler(bool requireToken, bool failTokenRequest = false)
            {
                _requireToken = requireToken;
                _failTokenRequest = failTokenRequest;
            }

            public bool TokenRequested { get; private set; }
            public bool RoleNameUsedToken { get; private set; }
            public bool CredentialsUsedToken { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var path = request.RequestUri.AbsolutePath.TrimEnd('/');
                var hasToken = false;
                if (request.Headers.TryGetValues(AlibabaCloudIdProvider.EcsMetadataTokenHeader, out var tokenValues))
                {
                    foreach (var value in tokenValues)
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            hasToken = true;
                            break;
                        }
                    }
                }

                if (request.Method == HttpMethod.Put && path == AlibabaCloudIdProvider.EcsMetadataTokenPath)
                {
                    TokenRequested = true;
                    if (_failTokenRequest)
                    {
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
                    }
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("imds-token"),
                    });
                }

                if (request.Method == HttpMethod.Get && path == AlibabaCloudIdProvider.EcsRamCredentialsPath.TrimEnd('/'))
                {
                    RoleNameUsedToken = hasToken;
                    return Metadata(hasToken, "AliyunECSRole");
                }

                if (request.Method == HttpMethod.Get && path == (AlibabaCloudIdProvider.EcsRamCredentialsPath + "AliyunECSRole").TrimEnd('/'))
                {
                    CredentialsUsedToken = hasToken;
                    return Metadata(hasToken,
                        "{\"AccessKeyId\":\"STS.AKID\",\"AccessKeySecret\":\"STSSECRET\",\"SecurityToken\":\"STSTOKEN\"}");
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            private Task<HttpResponseMessage> Metadata(bool hasToken, string body)
            {
                if (_requireToken && !hasToken)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body),
                });
            }
        }
    }
}
