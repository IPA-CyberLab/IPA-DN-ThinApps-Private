// Thin Telework System Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA CYBERLAB, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE IPA CYBERLAB HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


using System;
using System.Threading;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;

namespace BuildRelease
{
	public static class SignClient
	{
		const string SeInternalPasswordFilePath = @"\\labfs.lab.coe.ad.jp\share\tmp\signserver\password.txt";

		const string Url = "https://dn-labsign1.lab.coe.ad.jp:7006/sign";

		public static byte[] Sign(byte[] srcData, string certName, string flags, string comment)
		{
			string password = File.ReadAllText(SeInternalPasswordFilePath);

			string url = Url + "?password=" + password + "&cert=" + certName + "&flags=" + flags + "&comment=" + comment;

			ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
			WebRequest req = HttpWebRequest.Create(url);

			req.Timeout = 60 * 1000;
			req.Method = "POST";

			using (Stream reqs = req.GetRequestStream())
			{
				reqs.Write(srcData, 0, srcData.Length);

				reqs.Close();

				WebResponse res = req.GetResponse();

				using (Stream ress = res.GetResponseStream())
				{
					byte[] tmp = new byte[4 * 1024 * 1024];

					MemoryStream ms = new MemoryStream();

					while (true)
					{
						int r = ress.Read(tmp, 0, tmp.Length);
						if (r <= 0) break;

						ms.Write(tmp, 0, r);
					}

					return ms.ToArray();
				}
			}
		}
	}

	public static class CodeSign
	{
		public const int NumRetries = 1;
		public const int RetryIntervals = 200;

		public const int NumRetriesForCopy = 50;
		public const int RetryIntervalsForCopy = 10;

		public static int UsingCertId = 2;

		static object lockObj = new object();
		
		// Digital-sign the data on the memory
		public static byte[] SignMemory(byte[] srcData, string comment, bool kernelModeDriver, bool evCert)
		{
			// 2020/01/19 switch to the new system
			return SignClient.Sign(srcData, evCert ? "IpaFile" : "IpaFile", kernelModeDriver ? "Driver" : "", comment);
		}

		// Digital-sign the data on the file
		public static void SignFile(string destFileName, string srcFileName, string comment, bool kernelModeDriver, bool evCert)
		{

			Con.WriteLine("Signing for '{0}'...", Path.GetFileName(destFileName));
			byte[] srcData = File.ReadAllBytes(srcFileName);

			byte[] destData = SignMemory(srcData, comment, kernelModeDriver, evCert);

			try
			{
				File.Delete(destFileName);
			}
			catch
			{
			}

			File.WriteAllBytes(destFileName, destData);

			Con.WriteLine("Done.");
		}
	}
}

