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


#define	VPN_EXE
#define VARS_DEFINE_PATCH

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "ThinTest.h"
#include "Vars/VarsActivePatch.h"

static DS *dss = NULL;

void proxy_test(UINT num, char **arg)
{
	char *proxy_host = "proxy1.lab.coe.ad.jp";
	UINT proxy_port = 3128;

	char *server_host = "c20540145.controller.dynamic-ip.thin.cyber.ipa.go.jp";
	char *ua = DEFAULT_USER_AGENT;
	CONNECTION c = {0};

	SOCK *s;

	s = ProxyConnectEx2(&c, proxy_host, proxy_port, server_host, 443, NULL, NULL, false, NULL,
		NULL, 0, ua);

	if (s == NULL)
	{
		Print("ProxyConnectEx2 error.\n");
	}
	else
	{
		Print("ProxyConnectEx2 ok.\n");

		if (StartSSLEx(s, NULL, NULL, true, 0, server_host) == false)
		{
			Print("StartSSLEx error.\n");
		}
		else
		{
			UCHAR sha1[SHA1_SIZE] = {0};
			char tmp[MAX_SIZE];

			Print("StartSSLEx OK.\n");

			GetXDigest(s->RemoteX, sha1, true);

			BinToStr(tmp, sizeof(tmp), sha1, SHA1_SIZE);

			Print("Hash: %s\n", tmp);

			if (StrCmpi(tmp, "4498F763E7A6F3C971E20E40576684B3B353A515") == 0)
			{
				Print("Hash OK.\n");
			}
			else
			{
				Print("Hash NG. MITM.\n");
			}
		}

		Disconnect(s);
		ReleaseSock(s);
	}


}

void test(UINT num, char **arg)
{
}

void cc(UINT num, char **arg)
{
	WIDE *w = WideClientStart("DESK", _GETLANG());
	char *pcid = "pc6";
	UINT ret;
	SOCKIO *s;

	if (num >= 1)
	{
		pcid = arg[0];
	}

	ret = WideClientConnect(w, pcid, 0, 0, &s, 0, false);

	if (ret == ERR_NO_ERROR)
	{
		while (true)
		{
			UCHAR tmp[MAX_PATH];

			if (SockIoRecvAll(s, tmp, sizeof(tmp)) == false)
			{
				break;
			}

			Print("Recv: %s\n", tmp);
		}

		SockIoDisconnect(s);
		ReleaseSockIo(s);
	}

	WideClientStop(w);
}

void rdp_test_main(SOCKIO* sio, SOCK* s)
{
	SOCK_EVENT* e;
	FIFO* f1, * f2;
	void* buf;
	UINT buf_size;
	UINT64 disconnect_tick = 0;

	buf_size = 32767;

	buf = Malloc(buf_size);

	e = SockIoGetSockIoEvent(sio);
	JoinSockToSockEvent(s, e);

	f1 = NewFifo();
	f2 = NewFifo();

	SetSockEvent(e);

	while (true)
	{
		UINT ret;
		bool b = false;
		bool disconnected = false;

		WaitSockEvent(e, SELECT_TIME);

		do
		{
			b = false;

			// recv from socket
			while (FifoSize(f1) < WT_WINDOW_SIZE)
			{
				ret = Recv(s, buf, MIN(buf_size, WT_WINDOW_SIZE - FifoSize(f1)), false);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					WriteFifo(f1, buf, ret);
					//b = true;
				}
			}

			// recv from sockio
			while (FifoSize(f2) < WT_WINDOW_SIZE)
			{
				ret = SockIoRecvAsync(sio, buf, MIN(buf_size, WT_WINDOW_SIZE - FifoSize(f2)));
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					WriteFifo(f2, buf, ret);
					//b = true;
				}
			}

			// send to socket
			while (FifoSize(f2) != 0)
			{
				UINT size;
				UCHAR* p = (UCHAR*)f2->p + f2->pos;
				size = FifoSize(f2);

				ret = Send(s, p, size, false);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					ReadFifo(f2, NULL, ret);
					b = true;
				}
			}

			// send to sockio
			while (FifoSize(f1) != 0)
			{
				UINT size;
				UCHAR* p = (UCHAR*)f1->p + f1->pos;
				size = FifoSize(f1);

				ret = SockIoSendAsync(sio, p, size);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					ReadFifo(f1, NULL, ret);
					b = true;
				}
			}
		} while (b);

		if (disconnected)
		{
			if (disconnect_tick == 0)
			{
				disconnect_tick = Tick64();
			}

			if ((disconnect_tick + 1000) <= Tick64())
			{
				Print("Disconnected!!!!!!!!!!!\n");
				break;
			}
		}
	}

	ReleaseSockEvent(e);

	ReleaseFifo(f1);
	ReleaseFifo(f2);

	Free(buf);

	SleepThread(512);
}

void server_accept_test(THREAD* thread, SOCKIO* sock, void* param)
{
	SOCK_EVENT* e;
	UINT cmd = 0;

	Debug("Accepted.\n");

	e = SockIoGetSockIoEvent(sock);

	SockIoRecvAll(sock, &cmd, sizeof(UINT));

	if (cmd == 0)
	{
		// ping
		while (true)
		{
			UINT64 t;

			SockIoRecvAll(sock, &t, sizeof(t));
			if (SockIoSendAll(sock, &t, sizeof(t)) == false)
			{
				break;
			}
		}
	}
	else
	{
		// rdp
		SOCK* s = Connect("localhost", 3389);
		SetSocketSendRecvBufferSize(s->socket, WT_SOCKET_WINDOW_SIZE);

		if (s != NULL)
		{
			Debug("connect to localhost OK!\n");
			rdp_test_main(sock, s);

			Disconnect(s);
			ReleaseSock(s);
		}
	}

	Debug("Accept End.\n");

	ReleaseSockEvent(e);
}

void ss(UINT num, char **arg)
{
	WIDE *w = WideServerStart("DESK", server_accept_test, NULL, _GETLANG());
	X *x = FileToX("@user.cer");
	K *k = FileToK("@user.key", true, NULL);

	WideServerSetCertAndKey(w, x, k);

	if (0)
	{
		// 候補取得
		char cand[MAX_PATH];
		UINT ret = WideServerGetPcidCandidate(w, cand, sizeof(cand), NULL);

		if (ret != 0)
		{
			Print("WideServerGetPcidCandidate: %S\n", _E(ret));
		}
		else
		{
			Print("Candidate: %s\n", cand);
		}
	}

	if (0)
	{
		// 登録
		UINT ret = WideServerRegistMachine(w, "pc6", x, k);

		Print("WideServerRegistMachine: %S\n", _E(ret));
	}

	if (0)
	{
		// ログインしてみる
		WIDE_LOGIN_INFO info;
		UINT ret = WideServerGetLoginInfo(w, &info);
		if (ret != 0)
		{
			Print("WideServerGetLoginInfo: %S\n", _E(ret));
		}
		else
		{
			Print("Ok.\n");
		}
	}

	GetLine(NULL, 0);

	WideServerStop(w);

	FreeX(x);
	FreeK(k);
}

void gg(UINT num, char **arg)
{
	WIDE *w = WideGateStart();

	GetLine(NULL, 0);

	WideGateStop(w);
}

void ds(UINT num, char **arg)
{
	DS *ds = NewDs(true, false);

	GetLine(NULL, 0);

	FreeDs(ds);
}

bool dc_password_cb(DC_SESSION *s, char *password, UINT password_max_size)
{
	return false;
}

void dc_event_cb(DC_SESSION *s, UINT event_type, void *event_param)
{
	Print("Event: %u\n", event_type);
}

void dc(UINT num, char **arg)
{
	char *pcid = "d";
	DC *dc = NewDc(false);
	DC_SESSION *s;
	UINT ret;

	if (num >= 1)
	{
		pcid = arg[0];
	}

	if (true)
	{
		DcDownloadMstsc(dc, NULL, NULL);
	}

	NewDcSession(dc, pcid, dc_password_cb, NULL, NULL, dc_event_cb, NULL,
		NULL, &s);

	ret = DcSessionConnect(s);

	Print("%S\n", _E(ret));

	GetLine(NULL, 0);

	ReleaseDcSession(s);

	FreeDc(dc);
}

void dg(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DGExec();
#endif  // OS_WIN32
}

void du(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DUExec();
#endif  // OS_WIN32
}

void di(UINT num, char **arg)
{
#ifdef	OS_WIN32
	SWExec();
#endif  // OS_WIN32
}

void diu(UINT num, char **arg)
{
#ifdef	OS_WIN32
	//	DiDebugWithCommandLine("/UNINSTALL:1 /PRODUCT:1 /USERMODE:0 /PATH:\"C:\\Program Files\\Desktop VPN Server\"");
	DIExec(false);
#endif  // OS_WIN32
}

void rsa_test(UINT num, char **arg)
{
	UINT n = 1000;
	UINT i;
	UINT64 start;
	UINT64 span;
	K *priv, *pub;
	UCHAR src[128];
	UCHAR dst[128];
	UCHAR src2[128];
	if (num >= 1)
	{
		n = ToInt(arg[0]);
	}

	RsaGen(&priv, &pub, 1024);
	Rand(src, sizeof(src));

	Print("count: %u  start.\n", n);

	start = Tick64();

	for (i = 0;i < n;i++)
	{
		RsaPublicEncrypt(dst, src, 128, pub);
		RsaPrivateDecrypt(src2, dst, 128, priv);

		if (Cmp(src, src2, 128) != 0)
		{
			Print("Error.\n");
		}
	}

	span = Tick64() - start;

	Print("Time: %u msec.\n", span);
	Print("%.2f / 1 sec.\n", (double)n * 1000.0f / (double)span);

	FreeK(priv);
	FreeK(pub);
}

void download_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	char *pcid;
	UINT size;
	UINT ret;
	WIDE *wide;
	SOCKIO *sockio;
	if (num == 0)
	{
		Print("Usage: download pcid [size]\n");
		return;
	}

	pcid = arg[0];

	size = 1024 * 1024;
	if (num >= 2)
	{
		size = ToInt(arg[1]);
	}

	Print("Connecting...\n");

	wide = WideClientStart("DESK", _GETLANG());

	ret = WideClientConnect(wide, pcid, 0, 0, &sockio, 0, false);

	if (ret != ERR_NO_ERROR)
	{
		Print("%S\n", _E(ret));
	}
	else
	{
		PACK *p;
		void *data;
		UINT64 start, end;

		data = Malloc(size);

		p = NewPack();
		PackAddBool(p, "downloadmode", true);
		PackAddInt(p, "download_size", size);

		start = MsGetHiResCounter();
		SockIoSendPack(sockio, p);
		FreePack(p);

		if (SockIoRecvAll(sockio, data, size))
		{
			double span;
			UINT64 bps;
			char tmp[MAX_PATH];

			end = MsGetHiResCounter();

			p = NewPack();
			SockIoSendPack(sockio, p);
			FreePack(p);

			span = MsGetHiResTimeSpan(end - start);

			bps = (UINT64)((double)size * 8.0 / (double)(span));

			ToStr3(tmp, sizeof(tmp), bps);

			Print("%s bps", tmp);
		}
		else
		{
			Print("Disconnected!!\n");
		}

		Free(data);

		SockIoDisconnect(sockio);
	}

	WideClientStop(wide);
#endif  // OS_WIN32
}

void ping_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	char *pcid;
	UINT count;
	UINT ret;
	WIDE *wide;
	SOCKIO *sockio;
	if (num == 0)
	{
		Print("Usage: ping pcid [num]\n");
		return;
	}

	pcid = arg[0];

	count = 0x7FFFFFFF;
	if (num >= 2)
	{
		count = ToInt(arg[1]);
	}

	Print("Connecting...\n");

	wide = WideClientStart("DESK", _GETLANG());

	ret = WideClientConnect(wide, pcid, 0, 0, &sockio, 0, false);

	if (ret != ERR_NO_ERROR)
	{
		Print("%S\n", _E(ret));
	}
	else
	{
		UINT i, num;
		double total = 0;
		PACK *p;

		p = NewPack();
		PackAddBool(p, "pingmode", true);

		SockIoSendPack(sockio, p);
		FreePack(p);

		num = 0;

		for (i = 0;i < count;i++)
		{
			UINT64 tick1, tick2, now, diff;
			double diff_double;

			tick1 = MsGetHiResCounter();

			if (SockIoSendAll(sockio, &tick1, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			if (SockIoRecvAll(sockio, &tick2, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			now = MsGetHiResCounter();

			if (tick1 != tick2)
			{
				Print("Ping Protocol Error !!\n");
				break;
			}

			diff = now - tick2;
			diff_double = MsGetHiResTimeSpan(diff);

			if (count == 1 || i != 0)
			{
				total += diff_double;
				num++;
			}

			Print("Ping %u: %f sec.\n", num, diff_double);

			SleepThread(1000);
		}

		SockIoDisconnect(sockio);

		Print("Aver: %f sec (Count: %u)\n", (double)((double)total / (double)num), num);
	}

	WideClientStop(wide);
#endif  // OS_WIN32
}

// テスト関数一覧定義
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"test", test},
	{"ss", ss},
	{"gg", gg},
	{"cc", cc},
	{"ds", ds},
	{"dc", dc},
	{"dg", dg},
	{"du", du},
	{"di", di},
	{"diu", diu},
	{"ping", ping_test},
	{"down", download_test},
	{"rsa", rsa_test},
	{"proxy", proxy_test},
};

// テスト関数
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("Hamster Tester\n");
	OSSetHighPriority();

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
#ifdef	VISTA_HAM
			_exit(0);
#endif
			if (GetLine(tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), "q");
			}
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
#ifdef	VISTA_HAM
			if (EndWith(cmd, "vlan") == false)
			{
				_exit(0);
			}
#endif
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}


// main 関数
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;

	Vars_ApplyActivePatch();

	InitProcessCallOnceEx(true);

	printf("WideTunnel Test Program.\n");

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	DcSetDebugFlag(true);

	InitMayaqua(memchk, true, argc, argv);
	InitCedar();

	TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

