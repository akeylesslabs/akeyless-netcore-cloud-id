using Xunit;
using akeyless.Cloudid;

namespace AkeylessCloudId.Tests
{
    // Azure and GCP providers reach out to live metadata / credential endpoints in
    // GetCloudId(), which is not offline-provable. What we CAN assert without a
    // network is that they construct cleanly and honour the ICloudIdProvider
    // contract used by the factory and by downstream consumers.
    public class ProviderConstructionTests
    {
        [Fact]
        public void AzureProvider_ImplementsInterface()
        {
            var provider = new AzureCloudIdProvider();
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void GcpProvider_ImplementsInterface()
        {
            var provider = new GcpCloudIdProvider();
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void AwsProvider_ImplementsInterface()
        {
            var provider = new AwsCloudIdProvider();
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }

        [Fact]
        public void AlibabaProvider_ImplementsInterface()
        {
            var provider = new AlibabaCloudIdProvider();
            Assert.IsAssignableFrom<ICloudIdProvider>(provider);
        }
    }
}
