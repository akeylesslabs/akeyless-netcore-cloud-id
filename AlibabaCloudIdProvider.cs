using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace akeyless.Cloudid
{
    public class AlibabaCloudIdProvider : ICloudIdProvider
    {
        internal const string DefaultRegion = "cn-hangzhou";
        internal const string StsDomain = "sts.aliyuncs.com";
        internal const string StsApiVersion = "2015-04-01";
        internal const string StsApiAction = "GetCallerIdentity";
        internal const string StsApiFormat = "JSON";
        internal const string SignatureMethod = "HMAC-SHA1";
        internal const string EcsMetadataBaseUrl = "http://100.100.100.200";
        internal const string EcsMetadataTokenPath = "/latest/api/token";
        internal const string EcsRamCredentialsPath = "/latest/meta-data/ram/security-credentials/";
        internal const string EcsMetadataTokenHeader = "X-aliyun-ecs-metadata-token";
        internal const string EcsMetadataTokenTtlHeader = "X-aliyun-ecs-metadata-token-ttl-seconds";
        internal const string EcsMetadataTokenTtlSeconds = "60";

        private readonly HttpMessageHandler _metadataHandler;

        public AlibabaCloudIdProvider()
        {
        }

        internal AlibabaCloudIdProvider(HttpMessageHandler metadataHandler)
        {
            _metadataHandler = metadataHandler;
        }

        public string GetCloudId()
        {
            return GetCloudIdAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public async Task<string> GetCloudIdAsync()
        {
            var creds = await ResolveCredentialsAsync().ConfigureAwait(false);
            var region = ResolveRegion();
            if (string.IsNullOrEmpty(region))
            {
                region = DefaultRegion;
            }
            return SignRequest(creds.AccessKeyId, creds.AccessKeySecret, creds.SecurityToken, region,
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), Guid.NewGuid().ToString("N"));
        }

        internal string SignRequest(string accessKeyId, string accessKeySecret, string securityToken, string region, string timestamp, string nonce)
        {
            if (string.IsNullOrEmpty(region))
            {
                region = DefaultRegion;
            }
            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret))
            {
                throw new Exception("alibaba credentials are missing access key id or secret");
            }

            var queryParams = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                ["AccessKeyId"] = accessKeyId,
                ["Action"] = StsApiAction,
                ["Format"] = StsApiFormat,
                ["RegionId"] = region,
                ["SignatureMethod"] = SignatureMethod,
                ["SignatureNonce"] = nonce,
                ["SignatureType"] = "",
                ["SignatureVersion"] = "1.0",
                ["Timestamp"] = timestamp,
                ["Version"] = StsApiVersion,
            };
            if (!string.IsNullOrEmpty(securityToken))
            {
                queryParams["SecurityToken"] = securityToken;
            }

            var stringToSign = BuildRpcStringToSign("POST", queryParams);
            queryParams["Signature"] = ShaHmac1(stringToSign, accessKeySecret + "&");

            var requestUrl = "https://" + StsDomain + "/?" + EncodeQueryParams(queryParams);
            var headers = new Dictionary<string, string[]>
            {
                ["Content-Type"] = new[] { "application/x-www-form-urlencoded" },
                ["X-Acs-Action"] = new[] { StsApiAction },
                ["X-Acs-Version"] = new[] { StsApiVersion },
            };

            var payload = new Dictionary<string, string>
            {
                ["sts_request_method"] = "POST",
                ["sts_request_url"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(requestUrl)),
                ["sts_request_body"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("")),
                ["sts_request_headers"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(headers))),
            };
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
        }

        internal static string BuildRpcStringToSign(string method, IDictionary<string, string> queryParams)
        {
            var encoded = EncodeQueryParams(queryParams);
            encoded = encoded.Replace("+", "%20").Replace("*", "%2A").Replace("%7E", "~");
            return method + "&%2F&" + QueryEscape(encoded);
        }

        internal static string EncodeQueryParams(IDictionary<string, string> paramsDict)
        {
            var parts = new List<string>();
            foreach (var item in paramsDict)
            {
                parts.Add(QueryEscape(item.Key) + "=" + QueryEscape(item.Value ?? ""));
            }
            return string.Join("&", parts);
        }

        internal static string ShaHmac1(string source, string secret)
        {
            using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret)))
            {
                return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(source)));
            }
        }

        internal static string QueryEscape(string value)
        {
            return Uri.EscapeDataString(value ?? "").Replace("%20", "+").Replace("%7E", "~");
        }

        internal static string ResolveRegion()
        {
            foreach (var key in new[] { "ALIBABA_CLOUD_REGION_ID", "ALIBABA_CLOUD_REGION", "REGION_ID" })
            {
                var value = Environment.GetEnvironmentVariable(key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }
            return "";
        }

        internal static bool IsTruthyEnvValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }
            value = value.Trim();
            return value.Equals("true", StringComparison.OrdinalIgnoreCase)
                   || value.Equals("1", StringComparison.OrdinalIgnoreCase)
                   || value.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsImdsV1Disabled()
        {
            return IsTruthyEnvValue(Environment.GetEnvironmentVariable("ALIBABA_CLOUD_IMDSV1_DISABLED"))
                   || IsTruthyEnvValue(Environment.GetEnvironmentVariable("ALIBABA_CLOUD_IMDSV1_DISABLE"));
        }

        internal static HttpRequestMessage CreateImdsV2TokenRequest()
        {
            var request = new HttpRequestMessage(HttpMethod.Put, EcsMetadataBaseUrl + EcsMetadataTokenPath);
            request.Headers.TryAddWithoutValidation(EcsMetadataTokenTtlHeader, EcsMetadataTokenTtlSeconds);
            return request;
        }

        internal static HttpRequestMessage CreateImdsGetRequest(string url, string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.TryAddWithoutValidation(EcsMetadataTokenHeader, token);
            }
            return request;
        }

        internal static string FirstMetadataLine(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }
            var trimmed = value.Trim();
            var newline = trimmed.IndexOfAny(new[] { '\r', '\n' });
            return newline < 0 ? trimmed : trimmed.Substring(0, newline).Trim();
        }

        private async Task<AlibabaCredentials> ResolveCredentialsAsync()
        {
            var accessKeyId = FirstEnv("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY");
            var accessKeySecret = FirstEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_SECRET_KEY");
            var securityToken = FirstEnv("ALIBABA_CLOUD_SECURITY_TOKEN", "ALICLOUD_SECURITY_TOKEN");
            if (!string.IsNullOrEmpty(accessKeyId) && !string.IsNullOrEmpty(accessKeySecret))
            {
                return new AlibabaCredentials(accessKeyId, accessKeySecret, securityToken);
            }
            return await ResolveEcsRamRoleCredentialsAsync().ConfigureAwait(false);
        }

        private async Task<AlibabaCredentials> ResolveEcsRamRoleCredentialsAsync()
        {
            using (var client = CreateMetadataClient())
            {
                string token = null;
                try
                {
                    token = await FetchImdsV2TokenAsync(client).ConfigureAwait(false);
                }
                catch (Exception) when (!IsImdsV1Disabled())
                {
                    token = null;
                }

                var roleName = FirstMetadataLine(await GetMetadataAsync(client,
                    EcsMetadataBaseUrl + EcsRamCredentialsPath, token).ConfigureAwait(false));
                if (string.IsNullOrEmpty(roleName))
                {
                    throw new Exception("alibaba credentials are missing access key id or secret");
                }

                var body = await GetMetadataAsync(client,
                    EcsMetadataBaseUrl + EcsRamCredentialsPath + Uri.EscapeDataString(roleName), token)
                    .ConfigureAwait(false);
                var json = JObject.Parse(body);
                return new AlibabaCredentials(
                    json.Value<string>("AccessKeyId"),
                    json.Value<string>("AccessKeySecret"),
                    json.Value<string>("SecurityToken") ?? "");
            }
        }

        private HttpClient CreateMetadataClient()
        {
            var client = _metadataHandler != null
                ? new HttpClient(_metadataHandler, disposeHandler: false)
                : new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(2);
            return client;
        }

        private static async Task<string> FetchImdsV2TokenAsync(HttpClient client)
        {
            using (var request = CreateImdsV2TokenRequest())
            using (var response = await client.SendAsync(request).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                var token = (await response.Content.ReadAsStringAsync().ConfigureAwait(false)).Trim();
                if (string.IsNullOrEmpty(token))
                {
                    throw new Exception("alibaba ECS metadata token is empty");
                }
                return token;
            }
        }

        private static async Task<string> GetMetadataAsync(HttpClient client, string url, string token)
        {
            using (var request = CreateImdsGetRequest(url, token))
            using (var response = await client.SendAsync(request).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }

        private static string FirstEnv(params string[] keys)
        {
            foreach (var key in keys)
            {
                var value = Environment.GetEnvironmentVariable(key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }
            return "";
        }

        private sealed class AlibabaCredentials
        {
            public AlibabaCredentials(string accessKeyId, string accessKeySecret, string securityToken)
            {
                AccessKeyId = accessKeyId;
                AccessKeySecret = accessKeySecret;
                SecurityToken = securityToken;
            }

            public string AccessKeyId { get; }
            public string AccessKeySecret { get; }
            public string SecurityToken { get; }
        }
    }
}
