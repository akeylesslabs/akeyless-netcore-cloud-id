namespace akeyless.Cloudid;

public class Test
{
    static void Main(string[] args)
    {
        var cloudId = args[0];
        var cloudIdProvider = CloudIdProviderFactory.GetCloudIdProvider(cloudId);
        Console.WriteLine(cloudIdProvider.GetCloudId());
    }

}
