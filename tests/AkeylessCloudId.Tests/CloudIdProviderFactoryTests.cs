using System;
using Xunit;
using akeyless.Cloudid;

namespace AkeylessCloudId.Tests
{
    // Hermetic tests for the provider factory dispatch. No network, no credentials.
    public class CloudIdProviderFactoryTests
    {
        [Fact]
        public void GetCloudIdProvider_AwsIam_ReturnsAwsProvider()
        {
            var provider = CloudIdProviderFactory.GetCloudIdProvider("aws_iam");

            Assert.IsType<AwsCloudIdProvider>(provider);
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void GetCloudIdProvider_AzureAd_ReturnsAzureProvider()
        {
            var provider = CloudIdProviderFactory.GetCloudIdProvider("azure_ad");

            Assert.IsType<AzureCloudIdProvider>(provider);
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void GetCloudIdProvider_Gcp_ReturnsGcpProvider()
        {
            var provider = CloudIdProviderFactory.GetCloudIdProvider("gcp");

            Assert.IsType<GcpCloudIdProvider>(provider);
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void GetCloudIdProvider_Alicloud_ReturnsAlibabaProvider()
        {
            var provider = CloudIdProviderFactory.GetCloudIdProvider("alicloud");

            Assert.IsType<AlibabaCloudIdProvider>(provider);
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Theory]
        [InlineData("unknown")]
        [InlineData("AWS_IAM")]   // case sensitive: must not match "aws_iam"
        [InlineData("aws")]
        [InlineData("azure")]     // library expects "azure_ad", not "azure"
        [InlineData("")]
        public void GetCloudIdProvider_UnsupportedType_Throws(string accType)
        {
            var ex = Assert.Throws<Exception>(() => CloudIdProviderFactory.GetCloudIdProvider(accType));
            Assert.Contains("Unsupported type", ex.Message);
        }

        [Fact]
        public void GetCloudIdProvider_NullType_Throws()
        {
            Assert.Throws<Exception>(() => CloudIdProviderFactory.GetCloudIdProvider(null));
        }
    }
}
