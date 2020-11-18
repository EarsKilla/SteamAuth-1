using Newtonsoft.Json;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Threading;

namespace SteamAuth {
	/// <summary>
	/// Handles the linking process for a new mobile authenticator.
	/// </summary>
	public class AuthenticatorLinker {
		/// <summary>
		/// Set to register a new phone number when linking. If a phone number is not set on the account, this must be set. If a phone number is set on the account, this must be null.
		/// </summary>
		public string PhoneNumber = null;

		/// <summary>
		/// Randomly-generated device ID. Should only be generated once per linker.
		/// </summary>
		public string DeviceID { get; private set; }

		/// <summary>
		/// After the initial link step, if successful, this will be the SteamGuard data for the account. PLEASE save this somewhere after generating it; it's vital data.
		/// </summary>
		public SteamGuardAccount LinkedAccount { get; private set; }

		/// <summary>
		/// True if the authenticator has been fully finalized.
		/// </summary>
		public bool Finalized = false;

		private readonly SessionData Session;
		private readonly CookieContainer Cookies;
		private bool ConfirmationEmailSent = false;

		public AuthenticatorLinker(SessionData session) {
			Session = session;
			DeviceID = GenerateDeviceID();

			Cookies = new CookieContainer();
			session.AddCookies(Cookies);
		}

		public ELinkResult MoveAuthenticator() {
			NameValueCollection postData = new NameValueCollection {
				{ "donotcache", (TimeAligner.GetSteamTime() * 1000).ToString() }
			};

			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/login/getresetoptions/", "POST", postData, Cookies);
			if (response == null) {
				return ELinkResult.GeneralFailure;
			}

			ResetOptions resetOptions = JsonConvert.DeserializeObject<ResetOptions>(response);

			if (resetOptions.Success && resetOptions.options.sms.Allowed) {
				postData.Set("donotcache", (TimeAligner.GetSteamTime() * 1000).ToString());

				response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/login/startremovetwofactor/", "POST", postData, Cookies);
				if (response == null) {
					return ELinkResult.GeneralFailure;
				}

				AddPhoneResponse startRemoveResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
				if (startRemoveResponse.Success) {
					return ELinkResult.AwaitingFinalization;
				}
			}
			return ELinkResult.GeneralFailure;
		}

		public EFinalizeResult FinalizeMoveAuthenticator(string smsCode) {
			NameValueCollection postData = new NameValueCollection {
				{ "donotcache", (TimeAligner.GetSteamTime() * 1000).ToString() },
				{ "reset", "1" },
				{ "smscode", smsCode }
			};
			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/login/removetwofactor/", "POST", postData, Cookies);
			if (response == null) {
				return EFinalizeResult.GeneralFailure;
			}

			MoveResponse moveResponse = JsonConvert.DeserializeObject<MoveResponse>(response);
			if (moveResponse.Success == false) {
				return EFinalizeResult.GeneralFailure;
			}
			byte[] decodedResponse = System.Convert.FromBase64String(moveResponse.ReplacementToken);
			string decodedString = System.Text.Encoding.UTF8.GetString(decodedResponse);

			LinkedAccount = JsonConvert.DeserializeObject<SteamGuardAccount>(decodedString);
			LinkedAccount.Status = 1; //for compatibility
			LinkedAccount.Session = Session;
			LinkedAccount.DeviceID = DeviceID;
			LinkedAccount.FullyEnrolled = true;
			return EFinalizeResult.Success;
		}

		public ELinkResult AddAuthenticator() {
			bool hasPhone = HasPhoneAttached();
			if (hasPhone && PhoneNumber != null) {
				return ELinkResult.MustRemovePhoneNumber;
			}

			if (!hasPhone && PhoneNumber == null) {
				return ELinkResult.MustProvidePhoneNumber;
			}

			if (!hasPhone) {
				if (ConfirmationEmailSent) {
					if (!CheckEmailConfirmation()) {
						return ELinkResult.GeneralFailure;
					}
				} else if (!AddPhoneNumber()) {
					return ELinkResult.GeneralFailure;
				} else {
					ConfirmationEmailSent = true;
					return ELinkResult.MustConfirmEmail;
				}
			}

			NameValueCollection postData = new NameValueCollection {
				{ "access_token", Session.OAuthToken },
				{ "steamid", Session.SteamID.ToString() },
				{ "authenticator_type", "1" },
				{ "device_identifier", DeviceID },
				{ "sms_phone_id", "1" }
			};

			string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", postData);
			if (response == null) {
				return ELinkResult.GeneralFailure;
			}

			AddAuthenticatorResponse addAuthenticatorResponse = JsonConvert.DeserializeObject<AddAuthenticatorResponse>(response);
			if (addAuthenticatorResponse == null || addAuthenticatorResponse.Response == null) {
				return ELinkResult.GeneralFailure;
			}

			if (addAuthenticatorResponse.Response.Status == 29) {
				return ELinkResult.AuthenticatorPresent;
			}

			if (addAuthenticatorResponse.Response.Status != 1) {
				return ELinkResult.GeneralFailure;
			}

			LinkedAccount = addAuthenticatorResponse.Response;
			LinkedAccount.Session = Session;
			LinkedAccount.DeviceID = DeviceID;

			return ELinkResult.AwaitingFinalization;
		}

		public EFinalizeResult FinalizeAddAuthenticator(string smsCode) {
			//The act of checking the SMS code is necessary for Steam to finalize adding the phone number to the account.
			//Of course, we only want to check it if we're adding a phone number in the first place...

			if (!string.IsNullOrEmpty(PhoneNumber) && !CheckSMSCode(smsCode)) {
				return EFinalizeResult.BadSMSCode;
			}

			NameValueCollection postData = new NameValueCollection {
				{ "steamid", Session.SteamID.ToString() },
				{ "access_token", Session.OAuthToken },
				{ "activation_code", smsCode }
			};
			int tries = 0;
			while (tries <= 30) {
				postData.Set("authenticator_code", LinkedAccount.GenerateSteamGuardCode());
				postData.Set("authenticator_time", TimeAligner.GetSteamTime().ToString());

				string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", postData);
				if (response == null) {
					return EFinalizeResult.GeneralFailure;
				}

				FinalizeAuthenticatorResponse finalizeResponse = JsonConvert.DeserializeObject<FinalizeAuthenticatorResponse>(response);

				if (finalizeResponse == null || finalizeResponse.Response == null) {
					return EFinalizeResult.GeneralFailure;
				}

				if (finalizeResponse.Response.Status == 89) {
					return EFinalizeResult.BadSMSCode;
				}

				if (finalizeResponse.Response.Status == 88) {
					if (tries >= 30) {
						return EFinalizeResult.UnableToGenerateCorrectCodes;
					}
				}

				if (!finalizeResponse.Response.Success) {
					return EFinalizeResult.GeneralFailure;
				}

				if (finalizeResponse.Response.WantMore) {
					tries++;
					continue;
				}

				LinkedAccount.FullyEnrolled = true;
				return EFinalizeResult.Success;
			}

			return EFinalizeResult.GeneralFailure;
		}

		private bool CheckSMSCode(string smsCode) {
			NameValueCollection postData = new NameValueCollection {
				{ "op", "check_sms_code" },
				{ "arg", smsCode },
				{ "checkfortos", "0" },
				{ "skipvoip", "1" },
				{ "sessionid", Session.SessionID }
			};

			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, Cookies);
			if (response == null) {
				return false;
			}

			AddPhoneResponse addPhoneNumberResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);

			if (!addPhoneNumberResponse.Success) {
				Thread.Sleep(3500); //It seems that Steam needs a few seconds to finalize the phone number on the account.
				return HasPhoneAttached();
			}

			return true;
		}

		private bool AddPhoneNumber() {
			NameValueCollection postData = new NameValueCollection {
				{ "op", "add_phone_number" },
				{ "arg", PhoneNumber },
				{ "sessionid", Session.SessionID }
			};

			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, Cookies);
			if (response == null) {
				return false;
			}

			AddPhoneResponse addPhoneNumberResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
			return addPhoneNumberResponse.Success;
		}

		private bool CheckEmailConfirmation() {
			NameValueCollection postData = new NameValueCollection {
				{ "op", "email_confirmation" },
				{ "arg", "" },
				{ "sessionid", Session.SessionID }
			};

			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, Cookies);
			if (response == null) {
				return false;
			}

			AddPhoneResponse emailConfirmationResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
			return emailConfirmationResponse.Success;
		}

		private bool HasPhoneAttached() {
			NameValueCollection postData = new NameValueCollection {
				{ "op", "has_phone" },
				{ "arg", "null" },
				{ "sessionid", Session.SessionID }
			};

			string response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, Cookies);
			if (response == null) {
				return false;
			}

			HasPhoneResponse hasPhoneResponse = JsonConvert.DeserializeObject<HasPhoneResponse>(response);
			return hasPhoneResponse.HasPhone;
		}

		public enum ELinkResult {
			MustProvidePhoneNumber, //No phone number on the account
			MustRemovePhoneNumber, //A phone number is already on the account
			MustConfirmEmail, //User need to click link from confirmation email
			AwaitingFinalization, //Must provide an SMS code
			GeneralFailure, //General failure (really now!)
			AuthenticatorPresent
		}

		public enum EFinalizeResult {
			BadSMSCode,
			UnableToGenerateCorrectCodes,
			Success,
			GeneralFailure
		}

		private class AddAuthenticatorResponse {
			[JsonProperty("response")]
			public SteamGuardAccount Response { get; set; }
		}

		private class FinalizeAuthenticatorResponse {
			[JsonProperty("response")]
			public FinalizeAuthenticatorInternalResponse Response { get; set; }

			internal class FinalizeAuthenticatorInternalResponse {
				[JsonProperty("status")]
				public int Status { get; set; }

				[JsonProperty("server_time")]
				public long ServerTime { get; set; }

				[JsonProperty("want_more")]
				public bool WantMore { get; set; }

				[JsonProperty("success")]
				public bool Success { get; set; }
			}
		}

		private class ResetOptions {
			[JsonProperty("success")]
			public bool Success { get; set; }
			[JsonProperty("options")]

#pragma warning disable IDE1006 // Naming Styles
#pragma warning disable CS0649 // Unused fields
			public Options options;

			public sealed class Options {
				[JsonProperty("sms")]
				public Sms sms;
#pragma warning restore IDE1006  // Naming Styles
#pragma warning restore CS0649 // Unused fields
			}

			public sealed class Sms {
				[JsonProperty("allowed")]
				public bool Allowed { get; set; }
				[JsonProperty("last_digits")]
				public string LastDigits { get; set; }
			}
		}

		private class MoveResponse {
			[JsonProperty("success")]
			public bool Success { get; set; }

			[JsonProperty("replacement_token")]
			public string ReplacementToken { get; set; }
		}

		private class HasPhoneResponse {
			[JsonProperty("has_phone")]
			public bool HasPhone { get; set; }
		}

		private class AddPhoneResponse {
			[JsonProperty("success")]
			public bool Success { get; set; }
		}

		public static string GenerateDeviceID() => "android:" + Guid.NewGuid().ToString();
	}
}
