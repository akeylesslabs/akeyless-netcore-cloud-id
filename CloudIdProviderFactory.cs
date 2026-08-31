using System;

namespace akeyless.Cloudid
{

    public class CloudIdProviderFactory
    {
        public static ICloudIdProvider GetCloudIdProvider(string accType)
        {
            if (accType == "aws_iam")
            {
                return new AwsCloudIdProvider();
            }
            else if (accType == "azure_ad")
            {
                return new AzureCloudIdProvider();
            }
            else if (accType == "gcp")
            {
                return new GcpCloudIdProvider();
            }
            else if (accType == "ali_cloud")
            {
                return new AlibabaCloudIdProvider();
            }

            throw new Exception("Unsupported type: " + accType);
        }
    }
}