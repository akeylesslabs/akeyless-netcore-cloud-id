using System;
using System.Collections.Generic;
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

        public async Task<string> GetCloudIdAsync()
        {
            var creds = await ResolveCredentialsAsync();
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

        private static async Task<AlibabaCredentials> ResolveCredentialsAsync()
        {
            var accessKeyId = FirstEnv("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY");
            var accessKeySecret = FirstEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALICLOUD_SECRET_KEY");
            var securityToken = FirstEnv("ALIBABA_CLOUD_SECURITY_TOKEN", "ALICLOUD_SECURITY_TOKEN");
            if (!string.IsNullOrEmpty(accessKeyId) && !string.IsNullOrEmpty(accessKeySecret))
            {
                return new AlibabaCredentials(accessKeyId, accessKeySecret, securityToken);
            }
            return await ResolveEcsRamRoleCredentialsAsync();
        }

        private static async Task<AlibabaCredentials> ResolveEcsRamRoleCredentialsAsync()
        {
            using (var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(2) })
            {
                var roleName = (await client.GetStringAsync("http://100.100.100.200/latest/meta-data/ram/security-credentials/")).Trim();
                if (string.IsNullOrEmpty(roleName))
                {
                    throw new Exception("alibaba credentials are missing access key id or secret");
                }
                var body = await client.GetStringAsync("http://100.100.100.200/latest/meta-data/ram/security-credentials/" + roleName);
                var json = JObject.Parse(body);
                return new AlibabaCredentials(
                    json.Value<string>("AccessKeyId"),
                    json.Value<string>("AccessKeySecret"),
                    json.Value<string>("SecurityToken") ?? "");
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
