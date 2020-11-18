﻿using System;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json;

namespace SteamAuth {
	/// <summary>
	/// Class to help align system time with the Steam server time. Not super advanced; probably not taking some things into account that it should.
	/// Necessary to generate up-to-date codes. In general, this will have an error of less than a second, assuming Steam is operational.
	/// </summary>
	public class TimeAligner {
		private static bool Aligned = false;
		private static int TimeDifference = 0;

		public static long GetSteamTime() {
			if (!TimeAligner.Aligned) {
				TimeAligner.AlignTime();
			}
			return Util.GetSystemUnixTime() + TimeDifference;
		}

		public static async Task<long> GetSteamTimeAsync() {
			if (!TimeAligner.Aligned) {
				await TimeAligner.AlignTimeAsync();
			}
			return Util.GetSystemUnixTime() + TimeDifference;
		}

		public static void AlignTime() {
			long currentTime = Util.GetSystemUnixTime();
			using (WebClient client = new WebClient()) {
				try {
					string response = client.UploadString(APIEndpoints.TWO_FACTOR_TIME_QUERY, "steamid=0");
					TimeQuery query = JsonConvert.DeserializeObject<TimeQuery>(response);
					TimeAligner.TimeDifference = (int) (query.Response.ServerTime - currentTime);
					TimeAligner.Aligned = true;
				} catch (WebException) {
					return;
				}
			}
		}

		public static async Task AlignTimeAsync() {
			long currentTime = Util.GetSystemUnixTime();
			WebClient client = new WebClient();
			try {
				string response = await client.UploadStringTaskAsync(new Uri(APIEndpoints.TWO_FACTOR_TIME_QUERY), "steamid=0");
				TimeQuery query = JsonConvert.DeserializeObject<TimeQuery>(response);
				TimeAligner.TimeDifference = (int) (query.Response.ServerTime - currentTime);
				TimeAligner.Aligned = true;
			} catch (WebException) {
				return;
			}
		}

		internal class TimeQuery {
			[JsonProperty("response")]
			internal TimeQueryResponse Response { get; set; }

			internal class TimeQueryResponse {
				[JsonProperty("server_time")]
				public long ServerTime { get; set; }
			}

		}
	}
}
