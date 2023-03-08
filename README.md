# akeyless-dotnet-cloudid

Akeyless CloudId Provider

The purpose of this package is to exteact the required "cloudid" to authenticate to akeyless using cloud authorization providers.

For more information, please visit [https://akeyless.io](https://akeyless.io)

## Publishing a new version
Change the version in the .csproj file, tag the commit with a new tag (ie. v1.1.1) and push to the repository.
The workflow will build and publish a new version to the artifactory repository.

## Frameworks supported
- .NET Core >= 2.0
- .NET Framework >= 4.6
- Mono/Xamarin >= 5.4

## Dependancies
.NETStandard 2.0
AWSSDK.Core (>= 3.7.105.13)
Google.Apis.Auth (>= 1.56.0)
Newtonsoft.Json (>= 13.0.1)

## Installation
```
dotnet add package akeyless-dotnet-cloudid
```


## Getting Started

Please follow the [installation](#installation) instruction and execute the following c# code:

```csharp
using akeyless.Client;
using akeyless.Api;
using akeyless.Model;
using akeyless.Cloudid;

var host = "https://api.akeyless.io";

Configuration config = new Configuration();
config.BasePath = host;
var api = new V2Api(config);

// Use azure_ad/aws_iam/gcp, according to your cloud provider
var accessType = "aws_iam";
var cloudIdProvider = CloudIdProviderFactory.GetCloudIdProvider(accessType);
var cloudId = cloudIdProvider.GetCloudId();


Auth auth = new Auth();
auth.AccessId = "<your access id>";
auth.AccessType = accessType;
auth.CloudId = cloudId;

AuthOutput result = api.Auth(auth);

ListItems listBody = new ListItems();
listBody.Token = result.Token;
ListItemsInPathOutput listOut = api.ListItems(listBody);
Console.WriteLine(listOut.Items.Count);
 ```

## Author
support@akeyless.io

