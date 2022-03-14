
using System.Text;
using Newtonsoft.Json;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.Runtime.Internal.Auth;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;

namespace akeyless.Cloudid
{
    public class AwsCloudIdProvider : ICloudIdProvider
    {
        private static string ToHexString(IReadOnlyCollection<byte> array)
        {
            var hex = new StringBuilder(array.Count * 2);
            foreach (var b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
        public string SignRequest(string awsAccessId, string awsSecretAccessKey)
        {
            var algorithm = "AWS4-HMAC-SHA256";
            var service = "sts";
            var region = "us-east-1";
            var method = "POST";
            var host = "sts.amazonaws.com";
            var contentType = "application/x-www-form-urlencoded; charset=utf-8";
            var body = "Action=GetCallerIdentity&Version=2011-06-15";

            var t = DateTime.UtcNow;

            var amzDate = t.ToString("yyyyMMddTHHmmssZ");
            var datestamp = t.ToString("yyyyMMdd");

            var credentialScope = datestamp + '/' + region + '/' + service + '/' + "aws4_request";
            var canonicalUri = "/";
            var canonicalQuerystring = "";
            var signedHeaders = "content-length;content-type;host;x-amz-date";

            var hasher = SHA256.Create();
            var bodyDigest = ToHexString(hasher.ComputeHash(Encoding.UTF8.GetBytes(body)));

            var canonicalHeaders = string.Format("content-length:{0}\ncontent-type:{1}\nhost:{2}\nx-amz-date:{3}\n", body.Length, contentType, host, amzDate);

            var canonicalRequest = string.Format("{0}\n{1}\n{2}\n{3}\n{4}\n{5}", method, canonicalUri, canonicalQuerystring, canonicalHeaders, signedHeaders, bodyDigest);

            var canonicalHeaderHash = ToHexString(hasher.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)));

            var stringToSign = string.Format("{0}\n{1}\n{2}\n{3}", algorithm, amzDate, credentialScope, canonicalHeaderHash);


            hasher.Clear();
            hasher = SHA256.Create();
            // var signingKey = GetSignatureKey(awsSecretAccessKey, datestamp, region, service);
            var signingKey = AWS4Signer.ComposeSigningKey(awsSecretAccessKey, region, datestamp, "sts");
            var signature = ToHexString(AWS4Signer.ComputeKeyedHash(SigningAlgorithm.HmacSHA256, signingKey, stringToSign));


            var auth = string.Format("{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}",
                        algorithm, awsAccessId, credentialScope, signedHeaders, signature);

            var headers = new Dictionary<string, string[]>();

            headers["Authorization"] = new string[] { auth };
            headers["Content-Length"] = new string[] { body.Length.ToString() };
            headers["Content-Type"] = new string[] { contentType };
            headers["Host"] = new string[] { host };
            headers["X-Amz-Date"] = new string[] { amzDate };

            var headersJson = JsonConvert.SerializeObject(headers);

            var awsData = new Dictionary<string, string>();

            awsData["sts_request_method"] = method;
            awsData["sts_request_url"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("https://sts.amazonaws.com/"));
            awsData["sts_request_body"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(body));
            awsData["sts_request_headers"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(headersJson));

            var awsDump = JsonConvert.SerializeObject(awsData);

            var cloudId = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(awsDump));

            return cloudId;
        }

        public async Task<string> GetCloudIdAsync()
        {
            var chain = new CredentialProfileStoreChain();
            AWSCredentials awsCredentials;

            chain.TryGetAWSCredentials("default", out awsCredentials);

            var creds = await awsCredentials.GetCredentialsAsync();
            var accessKey = creds.AccessKey;
            var secretKey = creds.SecretKey;

            return SignRequest(accessKey, secretKey);
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