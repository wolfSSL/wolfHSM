# wolfHSMの始め方

wolfHSMの最も一般的な使用例は、HSMコプロセッサを搭載したマルチコアデバイスのアプリケーションコアの1つで動作する既存のアプリケーションに、HSM対応の機能を追加することです。

デバイス上でwolfHSMを実行するために必要な最初のステップは、特定のwolfHSMポートの手順に従って、HSMコア上でリファレンスサーバーを実行することです。wolfHSMサーバーアプリケーションがデバイスにロードされて起動すると、クライアントアプリケーションはwolfHSMクライアントライブラリとリンクし、wolfHSMクライアント構造体のインスタンスを設定して、wolfHSMクライアントAPIとwolfCrypt APIを通じてHSMと対話できるようになります。

各wolfHSMポートには、デフォルトの通信チャネルの設定方法とサーバーとの対話方法を示すクライアントデモアプリが含まれています。また、サーバーのリファレンス実装は[サーバーコールバック](./chapter07.md)によってカスタマイズでき、その機能はクライアントリクエストを通じて呼び出すことができます。

## 基本的なクライアント設定

wolfHSMクライアントを使用するには、クライアントコンテキスト構造体を割り当て、有効なクライアントのパラメータを用いて初期化処理を実行する必要があります。

クライアントコンテキスト構造体`whClientContext`は、クライアントの内部状態とサーバーとの通信を保持します。すべてのクライアントAPIは、クライアントコンテキストへのポインタを受け取ります。

クライアント設定構造体には、サーバーとの通信用にコンテキストを設定・初期化するために使用される通信レイヤー設定（`whCommClientConfig`）が含まれています。`whCommClientConfig`構造体は、実際のトランスポート実装（組み込みまたはカスタム）をクライアントが使用する抽象的な通信インターフェースにバインドします。

クライアントを設定する一般的な手順は以下の通りです。

1. 目的のトランスポートのトランスポート設定構造体、コンテキスト、コールバック実装を割り当て、初期化
2. 通信クライアント設定構造体を割り当て、手順1のトランスポート設定にバインド
3. 手順2の通信クライアント設定を使用してクライアント設定構造体を割り当て、初期化
4. クライアントコンテキスト構造体を割り当て
5. `wh_Client_Init()`を呼び出してクライアント設定でクライアントを初期化
6. クライアントAPIを使用してサーバーと接続

以下に、クライアントアプリケーション用の実装例を示します。
ここでは、組み込みの共有メモリトランスポートレイヤを使用して、サーバーにエコーリクエストを送信します。

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/client.h"  /* クライアントAPI（通信設定を含む） */
#include "wolfhsm/wh_transport_mem.h" /* トランスポート実装 */

/* 手順1: 共有メモリトランスポート設定の割り当てと初期化 */
/* 共有メモリトランスポート設定 */
static whTransportMemConfig transportMemCfg = { /* 共有メモリ設定 */ };
/* 共有メモリトランスポートコンテキスト（状態） */
whTransportMemClientContext transportMemClientCtx = {0};
/* 抽象的な通信トランスポートインターフェースを
   具体的な実装にバインドするコールバック構造体 */
whTransportClientCb transportMemClientCb = {WH_TRANSPORT_MEM_CLIENT_CB};

/* 手順2: クライアント通信設定を割り当て、トランスポートにバインド */
/* 選択したトランスポート設定を使用するようにクライアント通信を設定 */
whCommClientConfig commClientCfg = {
            .transport_cb      = transportMemClientCb,
            .transport_context = (void*)transportMemClientCtx,
            .transport_config  = (void*)transportMemCfg,
            .client_id         = 123, /* 一意のクライアント識別子 */
};

/* 手順3: クライアント設定の割り当てと初期化 */
whClientConfig clientCfg= {
  .comm = commClientCfg,
};

/* 手順4: クライアントコンテキストの割り当て */
whClientContext clientCtx = {0};

/* 手順5: 提供された設定でクライアントを初期化 */
wh_Client_Init(&clientCtx, &clientCfg);

/* 手順6: クライアントAPIを使用してサーバーと接続 */

/* 送受信データを保持するバッファ */
char recvBuffer[WH_COMM_DATA_LEN] = {0};
char sendBuffer[WH_COMM_DATA_LEN] = {0};

uint16_t sendLen = snprintf(&sendBuffer,
                           sizeof(sendBuffer),
                           "Hello World!\n");
uint16_t recvLen = 0;

/* エコーリクエストを送信し、応答を受信するまでブロック */
wh_Client_Echo(client, sendLen, &sendBuffer, &recvLen, &recvBuffer);

if ((recvLen != sendLen ) ||
   (0 != memcmp(sendBuffer, recvBuffer, sendLen))) {
   /* エラー：送信したものと同じものがエコーバックされなかった */
}
```

詳細については、[第5章：クライアントライブラリ](./chapter05.md)をご覧ください。

## 基本的なサーバ設定

*注：wolfHSMポートには、HSMコア上で実行するように設定済みのリファレンスサーバーアプリケーションが付属しているため、手動でのサーバー設定は必要ありません。*

wolfHSMサーバーを使用するには、サーバーコンテキスト構造体を割り当て、有効なクライアントのパラメータを用いてを初期化処理を実行する必要があります。
通常、クライアントとの通信、暗号化操作、鍵の管理、不揮発性オブジェクトの保存が含まれます。ただし、これらの設定コンポーネントをすべて初期化する必要はありません。必要なもののみ初期化します。

クライアント通信、NVMフラッシュ設定を使用したNVMオブジェクトストレージ、およびローカル暗号（ソフトウェアのみ）をサポートするサーバーを設定するために必要な手順を以下に示します。

1. サーバー通信設定の初期化
   1\. 目的のトランスポートのトランスポート設定構造体、コンテキスト、コールバック実装を割り当て、初期化
   2\. 手順1.1のトランスポート設定を使用して通信サーバー設定構造体を割り当て、初期化
2. サーバーNVMコンテキストの初期化
   1\. 低レベルフラッシュストレージドライバーの設定、コンテキスト、コールバック構造体を割り当て、初期化（これらの構造体の実装はポートによって提供されます）
   2\. NVMフラッシュ設定、コンテキスト、コールバック構造体を割り当て、初期化し、手順2.1のポートフラッシュ設定をそれらにバインド
   3\. NVMコンテキスト構造体を割り当て、`wh_Nvm_Init()`を使用して手順2.2の設定で初期化
3. サーバー用の暗号コンテキスト構造体を割り当て、初期化
4. wolfCryptを初期化（必ず、サーバーを初期化する前に行います）
5. サーバー設定構造体を割り当て、初期化し、通信サーバー設定、NVMコンテキスト、暗号コンテキストをバインド
6. サーバーコンテキスト構造体を割り当て、`wh_Server_Init()`を使用してサーバー設定で初期化
7. 基盤となるトランスポートがクライアント通信に使用できる準備が整い次第、`wh_Server_SetConnected()`を使用してサーバー接続状態を接続済みに設定（詳細については[サンプルプログラム](https://github.com/wolfSSL/wolfHSM/tree/main/examples)を参照ください）
8. `wh_Server_HandleRequestMessage()`を使用してクライアントリクエストを処理

サーバーは、NVMフラッシュ設定を使用してNVMオブジェクトストレージをサポートするように設定できます。
手順1の後に、サーバーで[NVMを初期化する](./chapter04.md#NVM-Architecture)手順を実行してください。

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/server.h"  /* サーバーAPI（通信設定を含む） */
#include "wolfhsm/wh_transport_mem.h" /* トランスポート実装 */

/* 手順1.1: 共有メモリトランスポート設定の割り当てと初期化 */
/* 共有メモリトランスポート設定 */
static whTransportMemConfig transportMemCfg = { /* 共有メモリ設定 */ };

/* 共有メモリトランスポートコンテキスト（状態） */
whTransportMemServerContext transportMemServerCtx = {0};

/* 抽象的な通信トランスポートインターフェースを
   具体的な実装にバインドするコールバック構造体 */
whTransportServerCb transportMemServerCb = {WH_TRANSPORT_MEM_SERVER_CB};

/* 手順1.2: 通信サーバー設定構造体を割り当て、
   トランスポートにバインド */
/* 選択したトランスポート設定を使用するようにサーバー通信を設定 */
whCommServerConfig commServerCfg = {
       .transport_cb       = transportMemServerCb,
       .transport_context  = (void*)transportMemServerCtx,
       .transport_config   = (void*)transportMemCfg,
       .server_id          = 456, /* 一意のサーバー識別子 */
};

/* サーバーNVMコンテキストの初期化 */

/* 手順2.1: ポート固有のフラッシュストレージドライバー用の
   コンテキストと設定の割り当てと初期化 */

/* ポートフラッシュコンテキスト（構造体名はポート固有） */
MyPortFlashContext portFlashCtx = {0}

/* ポートフラッシュ設定 */
MyPortFlashConfig portFlashCfg = { /* ポート固有の設定 */ };

/* ポートフラッシュ用のNVMフラッシュコールバック実装 */
whFlashCb portFlashCb = { /* NVMフラッシュコールバックのポートフラッシュ実装 */ };

/* 手順2.2: NVMフラッシュ設定構造体を割り当て、初期化し、
   手順2.1のポート設定にバインド */
whNvmFlashConfig nvmFlashCfg = {
   .cb         = portFlashCb,
   .context    = portFlashCtx,
   .config     = portFlashCfg,
};
whNvmFlashContext nfc = {0};

/* 手順2.3: NVMコンテキスト、設定、コールバック構造体を割り当て、
   手順2.2のNVMフラッシュ設定で初期化 */
whNvmCb nvmFlashCb = {WH_NVM_FLASH_CB};

whNvmConfig nvmConf = {
   .cb      = nvmFlashCb;
   .context = nfc;
   .config  = nvmFlashCfg,
};
whNvmContext nvmCtx = {0};

wh_Nvm_Init(&nvmCtx, &whNvmConfig);

/* 手順3: 暗号コンテキスト構造体の割り当てと初期化 */
whServerCryptoContext cryptoCtx {
   .devID = INVALID_DEVID; /* あるいは、カスタム暗号コールバックdevIDを設定 */
};

/* サーバー設定の割り当てと初期化 */
whServerConfig serverCfg = {
       .comm   = commServerCfg,
       .nvm    = nvmCtx,
       .crypto = cryptoCtx,
};

/* 手順4: wolfCryptの初期化 */
wolfCrypt_Init();

/* 手順5: サーバー設定構造体を割り当て、初期化し、
   通信サーバー設定と暗号コンテキストをバインド */
whServerContext server = {0};
wh_Server_Init(&server, &serverCfg);

/* トランスポートの準備が整い次第（例：共有メモリバッファがクリアされた後）、
   サーバー接続状態を接続済みに設定 */
wh_Server_SetConnected(&server, WH_COMM_CONNECTED);

/* クライアントリクエストの処理 */
while (1) {
   wh_Server_HandleRequestMessage(&server);
}
```
