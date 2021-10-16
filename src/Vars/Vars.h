// Thin Telework System Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.


#include "VarsCurrentBuildInfo.h"

// シン・テレワークシステム プライベート版構築者向け TODO:
// 以下の 2 つの項目の "Private" の文字列は、必ず変更し、ユニーク化すること。
// 詳しくは、構築マニュアル「8-2. アプリケーションの ID (AppId) の変更によるユニーク化」を参照すること。
#define APP_ID_PREFIX					"Private"
#define APP_ID_PREFIX_UNICODE			L"Private"

// シン・テレワークシステム プライベート版構築者向け TODO:
// 以下の "9825" (初期状態) の数字は、必ず変更し、ユニーク化すること。
// 詳しくは、構築マニュアル「8-2. アプリケーションの ID (AppId) の変更によるユニーク化」を参照すること。
#define DS_RPC_PORT						9825

// シン・テレワークシステム プライベート版構築者向け TODO:
// 以下の 4 つの各文字列内の "Private" という文字列の部分は、必ず変更し、ユニーク化すること。
// 詳しくは、構築マニュアル「8-2. アプリケーションの ID (AppId) の変更によるユニーク化」を参照すること。
#define DESK_PUBLISHER_NAME_ANSI		"Thin Telework System Private Version"
#define	DESK_PRODUCT_NAME_SUITE			"Thin Telework System Private Version"
#define	DESK_PRODUCT_NAME_SUITE_UNICODE		L"Thin Telework System Private Version"
#define DESK_PUBLISHER_NAME_UNICODE		L"Thin Telework System Private Version"


// シン・テレワークシステム プライベート版構築者向け TODO:
// 「DESK_LOCALHOST_DUMMY_FQDN」と「DESK_LOCALHOST_DUMMY_FQDN_V6」
// は、以下のサンプルのドメイン名を設定したままでも良いが、
// できるだけ自前ドメインに変更すること。
// この場合、"%s" の部分に任意の文字列が入った場合に
// 「DESK_LOCALHOST_DUMMY_FQDN」については 127.0.0.1 (IPv4 アドレス) が、
// 「DESK_LOCALHOST_DUMMY_FQDN_V6」については ::1 (IPv6 アドレス) が回答されるように
// DNS サーバーのゾーンファイルを設定すること。
#define DESK_LOCALHOST_DUMMY_FQDN		"%s.secure.ipantt.net"
#define DESK_LOCALHOST_DUMMY_FQDN_V6	"%s.secure6.ipantt.net"

// シン・テレワークシステム プライベート版構築者向け TODO:
// これは、シン・テレワークシステム クライアントの起動時にアップデートチェックを行なうための
// 最新ビルド情報の提供ファイル (HTTP で text/plain 応答がある) の URL である。
// 表記方法は、以下の URL のサンプルファイルを参照すること。
// 以下の URL は、シン・テレワークシステム パブリック版 https://telework.cyber.ipa.go.jp/ の
// 公式クライアントが参照するものである。
// ここで、テキストファイルの内容は 1 行目のコメントのとおり容易に理解することが可能と思われるが、
// "family" 列には上記の APP_ID_PREFIX の文字列に続けて "ThinClient" という文字列が付加された
// ものが指定される必要がある。
// すなわち、APP_ID_PREFIX 文字列が "Abc" の場合、応答テキストの "family" 列が
// "AbcThinClient" となっている行が応答される必要がある。
#define	UPDATE_SERVER_URL_GLOBAL		"https://update-check.dynamic-ip.thin.cyber.ipa.go.jp/update/?family=%s&software=%s&mybuild=%u&lang=%s"

// URDP ポート番号変更 (変更しないこと)
#undef	DS_URDP_PORT
#define DS_URDP_PORT					3459


