#:package AWSSDK.Core@3.7.501.1
#:include ../sdk/src/Core/Amazon.Runtime/Signing/SigV4SigningHandler.cs

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.Signing;

if (args.Length < 2 || !Uri.TryCreate(args[0], UriKind.Absolute, out var url) || url.Scheme != "https")
{
    Console.WriteLine("Usage: dotnet run --file samples/SigV4SigningHandler.cs -- <https-api-url> <region> [\"Header-Name: value\" ...]");
    return;
}

using var request = new HttpRequestMessage(HttpMethod.Get, url);
foreach (var header in args.Skip(2))
{
    var parts = header.Split(':', 2);
    if (parts.Length != 2)
        throw new ArgumentException("Headers must use 'Header-Name: value'.");
    request.Headers.Add(parts[0].Trim(), parts[1].Trim());
}

using var client = new HttpClient(new SigV4SigningHandler(
    FallbackCredentialsFactory.GetCredentials(), RegionEndpoint.GetBySystemName(args[1]), "execute-api"));

using var response = await client.SendAsync(request);
Console.WriteLine($"HTTP {(int)response.StatusCode}");
Console.WriteLine(await response.Content.ReadAsStringAsync());
