using System.Threading.Tasks;

namespace akeyless.Cloudid
{

    public interface ICloudIdProvider
    {
        Task<string> GetCloudIdAsync();
        string GetCloudId();
    }
}