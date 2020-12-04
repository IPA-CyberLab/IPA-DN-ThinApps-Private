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


void Vars_ApplyActivePatch();

#ifdef VARS_DEFINE_PATCH

void Vars_ApplyActivePatch()
{
	// Gate における古いバージョンの SSL/TLS の禁止フラグ
	Vars_ActivePatch_AddBool("WtGateDisableSsl3", true);
	Vars_ActivePatch_AddBool("WtGateDisableTls1_0", true);
	Vars_ActivePatch_AddBool("WtGateDisableTls1_1", true);

	// Entrance 設定ファイルに記載がないときのゲートウェイ表示文字列
	Vars_ActivePatch_AddStr("WtDefaultGatewaySystemName", "Thin Telework Private Version Sample Gateway");

	// 統計関係
	Vars_ActivePatch_AddStr("WtGateStatSystemName", "thingate_private");

#ifdef _WIN32
	Vars_ActivePatch_AddBitmap(D_ABOUT_BMP_ABOUTBOX, "AboutBox.bmp");
	Vars_ActivePatch_AddBitmap(D_SW_PERFORM_BMP_ABOUTBOX, "AboutBox.bmp");
	Vars_ActivePatch_AddBitmap(S_D_DU_MAIN_BANNER_BMP, "deskclient.bmp");
	Vars_ActivePatch_AddBitmap(D_DG_MAIN_BMP_DESKSERVER, "deskserver.bmp");
	Vars_ActivePatch_AddBitmap(D_DG_BMP_OTP, "Otp.bmp");
	Vars_ActivePatch_AddBitmap(D_DU_OTP_BMP_OTP, "Otp.bmp");
	Vars_ActivePatch_AddBitmap(D_SW_WELCOME_BMP_VPNSERVER_FIGURE, "VPNServerFigure.bmp");
#endif // _WIN32
}





#endif // VARS_DEFINE_PATCH

