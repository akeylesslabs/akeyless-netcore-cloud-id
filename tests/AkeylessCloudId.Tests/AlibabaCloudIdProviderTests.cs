using System;
using System.Collections.Generic;
using System.Text;
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
    }
}
