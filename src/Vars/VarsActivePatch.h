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
	// プライベート版かどうか
	Vars_ActivePatch_AddBool("IsPrivateVersion", true);

	// Gate における古いバージョンの SSL/TLS の禁止フラグ
	Vars_ActivePatch_AddBool("WtGateDisableSsl3", true);
	Vars_ActivePatch_AddBool("WtGateDisableTls1_0", true);
	Vars_ActivePatch_AddBool("WtGateDisableTls1_1", true);

	// Entrance 設定ファイルに記載がないときのゲートウェイ表示文字列
	Vars_ActivePatch_AddStr("WtDefaultGatewaySystemName", "Thin Telework Private Version Sample Gateway");

	// 統計関係
	Vars_ActivePatch_AddStr("WtGateStatSystemName", "thingate_private");

	// 完全閉域化ファイアウォール機能 (クライアント側)
	// サーバーのポリシー設定の如何にかかわらず、クライアント側で完全閉域化 FW を有効化する。
	// (0: 起動しない
	//  1: 起動する (ユーザーは ON/OFF を選択できる)
	//  2: 起動する (ユーザーは ON/OFF を選択できない。ユーザーが OFF にしようとすると接続を拒否する。
	//              実行ユーザーが Administrators 権限を有していない場合は、ON にできないので、
	//              接続ができなくなる。したがって、モード 2 は、実行ユーザーが確実に Administrators
	//              権限を有している場合のみ利用すること)
	Vars_ActivePatch_AddInt("ThinFwMode", 0);

	// サーバーのみのインストーラをビルドする場合は、以下の設定値を true にすること。
	// なお、ThinSetupServerOnly と ThinSetupClientOnly はいずれか一方しか指定できない。
	// 両方指定すると、全く意味のないインストーラが作成されてしまうので、注意すること。
	Vars_ActivePatch_AddBool("ThinSetupServerOnly", false);

	// クライアントのみのインストーラをビルドする場合は、以下の設定値を true にすること。
	// なお、ThinSetupServerOnly と ThinSetupClientOnly はいずれか一方しか指定できない。
	// 両方指定すると、全く意味のないインストーラが作成されてしまうので、注意すること。
	Vars_ActivePatch_AddBool("ThinSetupClientOnly", false);

	// ハイパースケール版のみ:
	// SMS をサポートする場合は true (中継ゲートウェイ側 DB も設定する必要がある。詳しくはハイパースケール版ドキュメントを参照せよ)
	Vars_ActivePatch_AddBool("ThinSupportSms", false);

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

