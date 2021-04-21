using System;
using System.Web;
using System.Threading;
using System.Collections;
using System.Configuration;
using System.Text;
using System.Net;
using System.IO;
using System.Collections.Specialized;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Diagnostics;

namespace SSOSecurity
{
    public  class SSOInformation
    {
		[JsonProperty("access_token")]
		public  string AccessToken { get; set; }

		[JsonProperty("token_type")]
		public  string TokenType { get; set; }

		[JsonProperty("expires_in")]
		public   int ExpiresIn { get; set; }

		[JsonProperty("refresh_token")]
		public  string RefreshToken { get; set; }
	}

	public class ErrorInformation
    {
		[JsonProperty("error")]
		public string Error { get; set; }
		[JsonProperty("error_description")]
		public string Error_Description { get; set; }
		[JsonProperty("Trace ID")]
		public string TraceID { get; set; }
		[JsonProperty("Correlation ID")]
		public string CorrelationID { get; set; }
		[JsonProperty("Timestamp")]
		public DateTime TimeStamp { get; set; }
    }
	/// <summary>
	/// Enables ASP.NET applications to use SSO authentication based on forms authentication. 
	/// This class cannot be inherited.
	/// </summary>
	public sealed class SSOAuthenticationModule : IHttpModule
	{
		HttpApplication app = null;
		const string LOGINURL_KEY				= "SSO.LoginURI";
	//	const string AUTHENTICATION_COOKIE_KEY	= "SSO.Cookie.Name";
		const string CLIENTID_KEY	= "SSO.ClientID";
		const string CLIENT_SECRET_KEY	= "SSO.ClientSecret";
		const string TENANTID_KEY	= "SSO.TenantID";
		const string SCOPE_KEY	= "SSO.Scope";
		const string REDIRECT_URI_KEY = "SSO.RedirectURI";
		const string TOKEN_URI_KEY = "SSO.TokenURI";


		/// <summary>
		/// Initializes the module derived from IHttpModule when called by the HttpRuntime . 
		/// </summary>
		/// <param name="httpapp">The HttpApplication module</param>
		public void Init(HttpApplication httpapp)
		{
			this.app = httpapp;
			app.AuthenticateRequest += new EventHandler(this.OnAuthenticate);
		}

		string GetTokenDetails(string base64String)
        {
			byte[] byteArr;
			try
			{
				byteArr = Convert.FromBase64String(base64String);
			}
			catch (FormatException)
			{
				byteArr = Convert.FromBase64String(base64String+"==");
			}
			var result = Encoding.UTF8.GetString(byteArr);
			return result;
		}
		void OnAuthenticate(object sender, EventArgs e)
		{
			app = (HttpApplication)sender;

		
			HttpRequest req = app.Request;
			HttpResponse res = app.Response;
			Debug.Write(req.IsAuthenticated);
			string cookieName = ".SSO_AUTH"; //ConfigurationManager.AppSettings[AUTHENTICATION_COOKIE_KEY];
			if (cookieName == null || cookieName.Trim() == String.Empty)
			{
				throw new Exception(" SSOAuthentication.Cookie.Name entry not found in appSettings section section of Web.config");
			}

			if (req.Cookies.Count > 0 && req.Cookies[".ASPXAUTH"] != null && req.Cookies[cookieName.ToUpper()] != null)
			{
				HttpCookie authCookie = req.Cookies[".ASPXAUTH"];
				if(authCookie != null)
                {
					HttpCookie cookie = req.Cookies[cookieName.ToUpper()];
					if (cookie != null)
					{
						string str = cookie.Value;
						SSOIdentity userIdentity = SSOAuthentication.Decrypt(str);
						string[] roles = userIdentity.UserRoles.Split(new char[] { '|' });
						ArrayList arrRoles = new ArrayList();
						arrRoles.InsertRange(0, roles);
						SSOPrincipal principal = new SSOPrincipal(userIdentity, arrRoles);
						app.Context.User = principal;
						Thread.CurrentPrincipal = principal;
					}
					return;
				}
				
			}

			string loginUrl = ConfigurationManager.AppSettings[LOGINURL_KEY];
			string clientID = ConfigurationManager.AppSettings[CLIENTID_KEY];
			string tenantID = ConfigurationManager.AppSettings[TENANTID_KEY];
			string scopes	= ConfigurationManager.AppSettings[SCOPE_KEY];
			string clientSecret = ConfigurationManager.AppSettings[CLIENT_SECRET_KEY];
			string redirectUri = ConfigurationManager.AppSettings[REDIRECT_URI_KEY];
			string tokenUri = ConfigurationManager.AppSettings[TOKEN_URI_KEY];
			
			if (loginUrl == null || loginUrl.Trim() == String.Empty)
			{
				throw new Exception(" SSOAuthentication.LoginUrl entry not found in appSettings section of Web.config");
			}
			loginUrl += $"/{tenantID}/oauth2/v2.0/authorize/?client_id={clientID}&response_type=code&scope={scopes}";


	
			if (req.QueryString.HasKeys() && req.QueryString.GetValues("code").Length>0)
			{
				string code = req.QueryString.GetValues("code")[0];

				WebClient wc = new WebClient();
				var reqparm = new NameValueCollection();
				reqparm.Add("client_id", clientID);
				reqparm.Add("scope", scopes);
				reqparm.Add("code", code);
				reqparm.Add("redirect_uri", redirectUri);
				reqparm.Add("grant_type", "authorization_code");
				reqparm.Add("client_secret", clientSecret);
				string reirUrl = tokenUri;
				HttpWebResponse httpResponse = null;
				string response = WebServiceRedirect(req, "application/x-www-form-urlencoded", "POST", reirUrl,reqparm, out httpResponse);
				ErrorInformation errors = JsonConvert.DeserializeObject<ErrorInformation>(response);
				if (errors != null && !string.IsNullOrEmpty(errors.Error) && errors.Error != null)
                {
					//JsonConvert.SerializeObject(errors);
					throw new Exception(JsonConvert.SerializeObject(errors));
				}

				SSOInformation tokeninfo = JsonConvert.DeserializeObject<SSOInformation>(response);
				if(tokeninfo != null)
                {
					var accessTokenArr = tokeninfo.AccessToken.Split('.');
					if (accessTokenArr.Length == 3)
					{
						var actualAccessToken = accessTokenArr[1];
						string decodedTokenValue = GetTokenDetails(actualAccessToken);

						Dictionary<string, object> tokenDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(decodedTokenValue);

						object userID, upk, email;
						tokenDict.TryGetValue("upn", out userID);
						tokenDict.TryGetValue("unique_name", out upk);
						tokenDict.TryGetValue("email", out email);

						SSOIdentity userIdentity = new SSOIdentity((string)userID, 0, true, false, "", (string)email, "");
						SSOPrincipal principal = new SSOPrincipal(userIdentity, null);
						app.Context.User = principal;
						Thread.CurrentPrincipal = principal;
						SSOAuthentication.RedirectFromLoginPage(userIdentity, tokeninfo.ExpiresIn);
                    }
                    else
                    {
						res.Redirect(loginUrl, true);
					}
				}
				
			}
			else
			{
				var b = Encoding.UTF8.GetBytes(req.Path);
				var str = Convert.ToBase64String(b);
				loginUrl += $"&state={str}";
				res.Redirect(loginUrl, true);
			}
		}

        private void Wc_UploadValuesCompleted(object sender, UploadValuesCompletedEventArgs e)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
		{
		}


		string WebServiceRedirect(HttpRequest request,string contentType,string method, string url, NameValueCollection nameValueCollection, out HttpWebResponse newResponse)
		{
			byte[] bytes = request.BinaryRead(request.TotalBytes);
			char[] responseBody = Encoding.UTF8.GetChars(bytes, 0, bytes.Length);

			HttpWebRequest newRequest = (HttpWebRequest)WebRequest.Create(url);
			newRequest.AllowAutoRedirect = false;
			newRequest.ContentType = contentType;// "application/x-www-form-urlencoded";
			newRequest.UseDefaultCredentials = true;
			newRequest.UserAgent = ".NET Web Proxy";
			newRequest.Referer = url;
			newRequest.Method = method;// "POST";

			StringBuilder parameters = new StringBuilder();

			foreach (string key in nameValueCollection.Keys)
			{
				parameters.AppendFormat("{0}={1}&",
					HttpUtility.UrlEncode(key),
					HttpUtility.UrlEncode(nameValueCollection[key]));
			}

			if (newRequest.Method.ToLower() == "post")
			{
				using (StreamWriter writer = new StreamWriter(newRequest.GetRequestStream()))
				{
					writer.Write(parameters.ToString());
				}
			}
			if (request.AcceptTypes.Length > 0)
				newRequest.MediaType = request.AcceptTypes[0];

			foreach (string str in request.Headers.Keys)
			{
				try { newRequest.Headers.Add(str, request.Headers[str]); }
				catch  { }
			}
			string temp = "";
			try
			{
				newResponse = (HttpWebResponse)newRequest.GetResponse();
				using (System.IO.StreamReader sw = new System.IO.StreamReader((newResponse.GetResponseStream())))
				{
					temp = sw.ReadToEnd();
					sw.Close();
				}
			}
			catch (WebException exc)
			{
				using (System.IO.StreamReader sw = new System.IO.StreamReader((exc.Response.GetResponseStream())))
				{
					newResponse = (HttpWebResponse)exc.Response;
					temp = sw.ReadToEnd();
					sw.Close();
				}
			}

			return temp;
		}
	}
}
