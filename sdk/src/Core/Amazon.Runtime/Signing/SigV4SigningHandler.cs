/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Auth;
using Amazon.Runtime.Internal.Util;

namespace Amazon.Runtime.Signing
{
    /// <summary>
    /// Signs buffered HTTP requests using the AWS SDK's Signature Version 4 signing engine.
    /// </summary>
    /// <remarks>
    /// Credentials are retrieved for each request. Any custom inner HTTP transport must have
    /// automatic redirects disabled so that redirected requests can be signed separately.
    /// </remarks>
    public class SigV4SigningHandler : DelegatingHandler
    {
        private readonly AWSCredentials _credentials;
        private readonly SigningClientConfig _config;

        /// <summary>
        /// Creates a signing handler for an AWS service and region.
        /// </summary>
        /// <param name="credentials">The credentials provider used to sign each request.</param>
        /// <param name="region">The region used in the signing scope.</param>
        /// <param name="service">The signing service name, such as "execute-api".</param>
        /// <param name="innerHandler">The transport handler, or null to use one with redirects disabled.</param>
        public SigV4SigningHandler(AWSCredentials credentials, RegionEndpoint region, string service,
            HttpMessageHandler innerHandler = null)
            : base(innerHandler ?? new HttpClientHandler { AllowAutoRedirect = false })
        {
            _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
            if (region == null)
                throw new ArgumentNullException(nameof(region));
            if (string.IsNullOrWhiteSpace(service))
                throw new ArgumentException("A signing service name is required.", nameof(service));

            _config = new SigningClientConfig(service)
            {
                RegionEndpoint = region,
                AuthenticationRegion = region.SystemName
            };
        }

        /// <summary>
        /// Signs the request and passes it to the inner handler.
        /// </summary>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            cancellationToken.ThrowIfCancellationRequested();
            var uri = request.RequestUri;
            if (uri == null || !uri.IsAbsoluteUri)
                throw new InvalidOperationException("The request URI must be an absolute URI.");

            var credentials = await _credentials.GetCredentialsAsync().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var signingRequest = new DefaultRequest(new SigningRequest(), _config.RegionEndpointServiceName)
            {
                HttpMethod = request.Method.Method,
                Endpoint = new Uri(uri.GetLeftPart(UriPartial.Authority)),
                ResourcePath = "/{Path+}",
                UseDoubleEncoding = false,
                UseQueryString = true,
                AuthenticationRegion = _config.AuthenticationRegion,
                OverrideSigningServiceName = _config.RegionEndpointServiceName,
                Content = request.Content == null ? Array.Empty<byte>() :
                    await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false)
            };
            cancellationToken.ThrowIfCancellationRequested();
            signingRequest.AddPathResource("{Path+}", uri.AbsolutePath.Substring(1));
            foreach (var parameter in uri.Query.TrimStart('?')
                .Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Split(new[] { '=' }, 2))
                .GroupBy(pair => WebUtility.UrlDecode(pair[0]), StringComparer.Ordinal))
            {
                signingRequest.ParameterCollection.Add(parameter.Key,
                    parameter.Select(pair => pair.Length == 2 ? WebUtility.UrlDecode(pair[1]) : string.Empty).ToList());
            }

            request.Headers.Remove("Authorization");
            request.Headers.Remove("X-Amz-Date");
            request.Headers.Remove("X-Amz-Security-Token");
            request.Headers.Remove("X-Amz-Content-SHA256");
            foreach (var header in request.Headers)
                signingRequest.Headers[header.Key] = string.Join(", ", header.Value.Select(value => value?.Trim() ?? string.Empty));
            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                {
                    var contentValue = string.Join(", ", header.Value.Select(value => value?.Trim() ?? string.Empty));
                    signingRequest.Headers[header.Key] = signingRequest.Headers.TryGetValue(header.Key, out var requestValue)
                        ? requestValue + "," + contentValue
                        : contentValue;
                }
            }
            if (credentials.UseToken)
                signingRequest.Headers["X-Amz-Security-Token"] = credentials.Token;

            var signature = new AWS4Signer().SignRequest(signingRequest, _config,
                new RequestMetrics(), credentials.AccessKey, credentials.SecretKey);
            request.Headers.TryAddWithoutValidation("Authorization", signature.ForAuthorizationHeader);
            foreach (var name in new[] { "Host", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-SHA256" })
            {
                if (signingRequest.Headers.TryGetValue(name, out var value))
                {
                    request.Headers.Remove(name);
                    request.Headers.TryAddWithoutValidation(name, value);
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private sealed class SigningRequest : AmazonWebServiceRequest
        {
        }

        private sealed class SigningClientConfig : ClientConfig
        {
            private readonly string _service;

            public SigningClientConfig(string service)
            {
                _service = service;
            }

            public override string RegionEndpointServiceName => _service;
            public override string ServiceVersion => string.Empty;
            public override string UserAgent => string.Empty;
        }
    }
}
