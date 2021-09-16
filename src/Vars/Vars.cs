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


public static class Vars
{
    // シン・テレワークシステム プライベート版構築者向け TODO:
    // 以下は、ソフトウェア中の表示文字列である。適宜書き換えること。
    public static readonly string ProductName = "Thin Telework System Private Version by NTT-EAST and IPA";
    public static readonly string CompanyName = "NTT-East and IPA Anti-Corona Virus Telework Special Project";
    public static readonly string Copyright = "Information-technology Promotion Agency, Nippon Telegraph and Telephone East Corporation, and all contributors. All rights reserved.";

    // シン・テレワークシステム プライベート版構築者向け TODO:
    // 以下の項目の "Private" の文字列は、必ず変更し、ユニーク化すること。
    // 詳しくは、構築マニュアル「8-2. アプリケーションの ID (AppId) の変更によるユニーク化」を参照すること。
    // この値は、Vars.h の APP_ID_PREFIX の文字列と一致させる必要がある。
    public static readonly string APP_ID_PREFIX = "Private";

    // 以下は、このままでよい。変更する必要はない。
    public static readonly string DistibutionPackagePrefix = APP_ID_PREFIX + "_";
}

