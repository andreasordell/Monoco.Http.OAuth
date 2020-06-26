using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Monoco.Http.OAuth.Handlers
{

    public class OAuthSigningHandler : DelegatingHandler
    {
        private string _consumerKey;
        private string _consumerSecret;
        
        public OAuthSigningHandler(OAuthSigningHandlerOptions options)
        {
            _consumerSecret = options.ConsumerSecret;
            _consumerKey = options.ConsumerKey;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Get the OAuth signed URL
            var oauthUriString = GenerateOAuthRequestUrl(request.RequestUri, request.Method.ToString(), _consumerKey, _consumerSecret);
            request.RequestUri = new Uri(oauthUriString);

            return await base.SendAsync(request, cancellationToken);
        }
        private string GenerateOAuthRequestUrl(Uri uri, string method, string consumerKey, string consumerSecret)
        {
            if (string.IsNullOrWhiteSpace(consumerKey)) throw new ArgumentNullException("consumerKey");
            if (string.IsNullOrWhiteSpace(consumerSecret)) throw new ArgumentNullException("consumerSecret");

            var normalizedUrl = "";
            var normalizedParams = "";

            var oAuth = new OAuthBase();
            var nonce = oAuth.GenerateNonce();
            var timeStamp = oAuth.GenerateTimeStamp();
            var sig =
                HttpUtility.UrlEncode(oAuth.GenerateSignature(uri, consumerKey, consumerSecret, "", "", method, timeStamp,
                                                              nonce, OAuthBase.SignatureTypes.HMACSHA1, out normalizedUrl,
                                                              out normalizedParams));
            var requestUrl = normalizedUrl + "?" + normalizedParams + "&oauth_signature=" + sig;
            return requestUrl.Replace("\"", "");
        }
    }
}
