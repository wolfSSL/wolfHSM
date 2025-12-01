# クライアントライブラリ

クライアントライブラリAPIは、ユーザーがwolfHSMと対話するための主要な手段です。
利用可能な関数の完全なリストとその説明については、[APIドキュメント](appendix01.md)をご参照ください。

## APIの返り値

すべてのクライアントAPI関数は、成功または失敗の種類を示すwolfHSMエラーコードを返します。
一部の失敗は重大なエラーですが、他の失敗は単にユーザーからのアクションが必要であることを示すものもあります（例：ノンブロッキング操作の場合の`WH_ERROR_NOTREADY`）。
多くのクライアントAPIは、サーバーエラーコード（場合によっては追加のステータス）もユーザーに伝達します。
これにより、基礎となるリクエストトランザクションは成功したものの、サーバーが操作を実行できなかった場合にも対応できます。
例えば、存在しないNVMオブジェクトをサーバーに要求した場合、NVMが満杯時にオブジェクトを追加しようとした場合、またはサーバーが対応するように設定されていない暗号化アルゴリズムを使用しようとした場合などが該当します。

エラーコードは`wolfhsm/wh_error.h`で定義しています。詳細については、APIドキュメントをご参照ください。

## 分割トランザクション処理

ほとんどのクライアントAPIは完全に非同期で、分割トランザクションに分解されています。
つまり、操作リクエストとレスポンスについて別々の関数があります。
リクエスト関数はサーバーにリクエストを送信し、ブロックせずに即座に戻ります。
レスポンス関数は基礎となるトランスポートをポーリングしてレスポンスを確認し、レスポンスが存在する場合は処理を行い、まだ到着していない場合は即座に戻ります。
これにより、クライアントのCPUサイクルを無駄にすることなく、サーバーに長時間実行される操作をリクエストできます。
以下に、「echo」メッセージを使用した非同期リクエストとレスポンスの呼び出し例を示します。

```c
int rc;

/* echoリクエストを送信 */
rc = wh_Client_EchoRequest(&clientCtx, sendLen, &sendBuffer);
if (rc != WH_ERROR_OK) {
    /* エラー処理 */
}

/* 他の処理を実行... */

/* サーバーレスポンスをポーリング */
while ((rc = wh_Client_EchoResponse(client, &recv_len, recv_buffer)) == WH_ERROR_NOTREADY) {
    /* 他の処理を実行するか、または制御を譲る */
}

if (rc != WH_ERROR_OK) {
    /* エラー処理 */
}
```

## クライアントコンテキスト

クライアントコンテキスト構造体（`whClientContext`）は、クライアントの実行時状態を保持し、サーバーとの接続のエンドポイントを表します。
また、クライアントとサーバーのコンテキストは1対1の関係にあります。つまり複数のサーバーと対話するアプリケーションでは、サーバーごとに1つのクライアントコンテキストが必要になります。
各クライアントAPI関数は、クライアントコンテキストを引数として受け取り、どのサーバー接続に対応する操作かを示します。
wolfSSLに慣れている方であれば、`WOLFSSL`接続コンテキスト構造体と同様の使い方をするとご認識いただいてよいかもしれません。

### クライアントコンテキストの初期化

クライアントコンテキストで任意のクライアントAPIを使用する前に、`whClientConfig`設定構造体と`wh_Client_Init()`関数を使用して構造体を設定し、初期化する必要があります。

クライアント設定構造体は、サーバー通信のためのコンテキストを設定・初期化するために使用される通信層設定（`whCommClientConfig`）を保持します。
`whCommClientConfig`構造体は、実際のトランスポート実装（組み込みまたはカスタム）を、クライアントが使用する抽象的な通信インターフェースにバインドします。

クライアントを設定する一般的な手順は以下の通りです。

1. 目的のトランスポートのためのトランスポート設定構造体、コンテキスト、およびコールバック実装を割り当てて初期化する
2. 通信クライアント設定構造体を割り当て、クライアントが使用できるようにステップ1のトランスポート設定にバインドする
3. ステップ2の通信クライアント設定を使用してクライアント設定構造体を割り当てて初期化する
4. クライアントコンテキスト構造体を割り当てる
5. `wh_Client_Init()`を呼び出してクライアント設定でクライアントを初期化する
6. クライアントAPIを使用してサーバーと接続する

以下に、組み込みの共有メモリトランスポートを使用するクライアントアプリケーションの設定例を示します。

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/client.h"  /* クライアントAPI（通信設定を含む） */
#include "wolfhsm/wh_transport_mem.h" /* トランスポート実装 */

/* ステップ1: 共有メモリトランスポート設定の割り当てと初期化 */
/* 共有メモリトランスポート設定 */
static whTransportMemConfig transportMemCfg = { /* 共有メモリ設定 */ };
/* 共有メモリトランスポートコンテキスト（状態） */
whTransportMemClientContext transportMemClientCtx = {0};
/* 抽象的な通信トランスポートインターフェースを
 * 具体的な実装にバインドするコールバック構造体 */
whTransportClientCb transportMemClientCb = {WH_TRANSPORT_MEM_CLIENT_CB};

/* ステップ2: クライアント通信設定の割り当てとトランスポートへのバインド */
/* 選択したトランスポート設定を使用するようにクライアント通信を設定 */
whCommClientConfig commClientCfg[1] = {{
             .transport_cb      = transportMemClientCb,
             .transport_context = (void*)transportMemClientCtx,
             .transport_config  = (void*)transportMemCfg,
             .client_id         = 123, /* 一意のクライアント識別子 */
}};

/* ステップ3: クライアント設定の割り当てと初期化 */
whClientConfig clientCfg= {
   .comm = commClientCfg,
};

/* ステップ4: クライアントコンテキストの割り当て */
whClientContext clientCtx = {0};

/* ステップ5: 提供された設定でクライアントを初期化 */
wh_Client_Init(&clientCtx, &clientCfg);
```

これでクライアントコンテキストが初期化され、作業を実行するためにクライアントライブラリAPI関数で使用できるようになりました。
引き続き、サーバーにechoリクエストを送信してみます。

```c
/* ステップ6: クライアントAPIを使用してサーバーと対話 */

/* 送受信データを保持するバッファ */
char recvBuffer[WH_COMM_DATA_LEN] = {0};
char sendBuffer[WH_COMM_DATA_LEN] = {0};

uint16_t sendLen = snprintf(&sendBuffer,
                            sizeof(sendBuffer),
                            "Hello World!\n");
uint16_t recvLen = 0;

/* echoリクエストを送信し、レスポンスを受信するまでブロック */
wh_Client_Echo(client, sendLen, &sendBuffer, &recvLen, &recvBuffer);

if ((recvLen != sendLen ) ||
    (0 != memcmp(sendBuffer, recvBuffer, sendLen))) {
    /* エラー：送信したものと同じものが返ってこなかった */
}
```

設定と構造体の組み合わせが少々複雑だと感じるかもしれません。
しかし、これによりクライアントコードを変更することなく、異なるトランスポート実装に簡単に入れ替えられるようにしています。
例えば、共有メモリトランスポートからTCPトランスポートに切り替える場合、トランスポート設定とコールバック構造体を変更するだけで済み、クライアントコードの残りの部分（上記の手順2以降のすべて）は同じままです。

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/client.h"  /* クライアントAPI（通信設定を含む） */
#include "port/posix_transport_tcp.h" /* トランスポート実装 */

/* ステップ1: POSIX TCPトランスポート設定の割り当てと初期化 */
/* クライアント設定/コンテキスト */
whTransportClientCb posixTransportTcpCb = {PTT_CLIENT_CB};
posixTransportTcpClientContext posixTranportTcpCtx = {0};
posixTransportTcpConfig posixTransportTcpCfg = {
    /* IPとポートの設定 */
};

/* ステップ2: クライアント通信設定の割り当てとトランスポートへのバインド */
/* 選択したトランスポート設定を使用するようにクライアント通信を設定 */
whCommClientConfig commClientCfg = {{
             .transport_cb      = posixTransportTcpCb,
             .transport_context = (void*)posixTransportTcpCtx,
             .transport_config  = (void*)posixTransportTcpCfg,
             .client_id         = 123, /* 一意のクライアント識別子 */
}};

/* 以降のステップは同じ... */
```

ステップ6のechoリクエストはあくまでも単純な使用例です。
サーバーとの接続が設定されれば、任意のクライアントAPIを使用できます。

## 不揮発性メモリ操作

このセクションでは、クライアントNVM APIの使用方法の例を示します。
分割トランザクションAPIも同様に使用できますが、簡単のためにブロッキングAPIを使用します。

クライアントがサーバーのNVMストレージを使用するには、まず初期化リクエストをサーバーに送信します。
現時点では、これによってサーバー側で何らかのアクションが実行されることはありません。
しかし将来的にはここに実装を加える可能性があるため、クライアントアプリケーションに初期化リクエストを含めることを推奨します。

```c
int rc;
int serverRc;
uint32_t clientId; /* 現時点では未使用 */
uint32_t serverId;

rc = wh_Client_NvmInit(&clientCtx, &serverRc, &clientId, &serverId);

/* ローカルとリモートの両方のエラーコードをチェック */
/* serverIdにはサーバーの一意のIDが格納される */
```

初期化が完了すると、クライアントは`NvmAddObject`関数を使用してオブジェクトを作成し追加できます。
すべてのオブジェクトに対してメタデータエントリを作成する必要があることに注意してください。

```c
int serverRc;

whNvmId id = 123;
whNvmAccess access = WOLFHSM_NVM_ACCESS_ANY;
whNvmFlags flags = WOLFHSM_NVM_FLAGS_ANY;
uint8_t label[] = “My Label”;

uint8_t myData[] = “This is my data.”

whClient_NvmAddObject(&clientCtx, id, access, flags, strlen(label), &label, sizeof(myData), &myData, &serverRc);
```

既存のオブジェクトに対応するデータは、その場で更新できます。

```c
byte myUpdate[]	= “This is my update.”

whClient_NvmAddObject(&clientCtx, &myMeta, sizeof(myUpdate), myUpdate);
```

トランスポート経由でコピーして送信すべきでないオブジェクトについては、`NvmAddObject`関数のDMAバージョンを使用できます。
これらは値ではなく参照によってデータをサーバーに渡すため、サーバーが直接メモリ内のデータにアクセスできます。
ただし、サーバーがクライアントのアドレスにアクセスする前に、プラットフォームがカスタムのアドレス変換またはキャッシュ無効化を必要とする場合は、[DMAコールバック](./chapter07#DMA-Callbacks)を実装する必要があることにご注意ください。

```c
whNvmMetadata myMeta = {
  .id = 123,
  .access = WOLFHSM_NVM_ACCESS_ANY,
  .flags = WOLFHSM_NVM_FLAGS_ANY,
  .label = “My Label”
};


uint8_t myData[] = “This is my data.”

wh_Client_NvmAddObjectDma(client, &myMeta, sizeof(myData), &myData), &serverRc);
```

NVMオブジェクトのデータは`NvmRead`関数を使用して読み取ることができます。
また、`AddObjectDma`に対応する`NvmRead`関数のDMAバージョンも存在し、同様に使用できます。

```c
const whNvmId myId = 123; /* 読み取りたいオブジェクトのID */
const whNvmSize offset = 0; /* オブジェクトデータへのバイトオフセット */

whNvmSize outLen; /* リクエストされたデータのバイト長が格納される */
int outRc; /* サーバーのリターンコードが格納される */

byte myBuffer[BIG_SIZE];

whClient_NvmRead(&clientCtx, myId, offset, sizeof(myData), &serverRc, outLen, &myBuffer)
/* または DMA経由で */
whClient_NvmReadDma(&clientCtx, myid, offset, sizeof(myData), &myBuffer, &serverRc);
```

オブジェクトは`NvmDestroy`関数を使用して削除/破棄できます。
これらの関数は、削除するオブジェクトIDのリスト（配列）を引数に取ります。
リスト内のIDがNVMに存在しない場合でもエラーは発生しません。

```c
whNvmId idList[] = {123, 456};
whNvmSize count = sizeof(myIds)/ sizeof(myIds[0]);
int serverRc;

wh_Client_NvmDestroyObjectsRequest(&clientCtx, count, &idList);
wh_Client_NvmDestroyObjectsResponse(&clientCtx, &serverRc);
```

NVM内のオブジェクトは、`NvmList`関数を使用して列挙できます。
この関数は、`start_id`から始まるNVMリスト内の次にマッチするIDを取得し、`access`と`flags`にマッチするIDの総数を`out_count`に設定します。

```c
int wh_Client_NvmList(whClientContext* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        int32_t *out_rc, whNvmId *out_count, whNvmId *out_id);
```

すべてのNVM API関数の詳細な説明については、[APIドキュメント](./appendix01.md)をご参照ください。

## 鍵管理

wolfCryptで使用することを意図した鍵は、以下のAPIを使用してHSMのキーストアにロードし、必要に応じてNVMに保存できます。

```c
#include "wolfhsm/wh_client.h"

uint16_t keyId = WOLFHSM_KEYID_ERASED;
uint32_t keyLen;
byte key[AES_128_KEY_SIZE] = { /* AES鍵 */ };
byte label[WOLFHSM_NVM_LABEL_LEN] = { /* 鍵ラベル */ };

whClientContext clientCtx;
whClientCfg clientCfg = { /* 設定 */ };

wh_Client_Init(&clientCtx, &clientCfg);

wh_Client_KeyCache(clientCtx, 0, label, sizeof(label), key, sizeof(key), &keyId);
wh_Client_KeyCommit(clientCtx, keyId);
wh_Client_KeyEvict(clientCtx, keyId);
keyLen = sizeof(key);
wh_Client_KeyExport(clientCtx, keyId, label, sizeof(label), key, &keyLen);
wh_Client_KeyErase(clientCtx, keyId);
```

`wh_Client_KeyCache`は、鍵とラベルをHSMのRAMキャッシュに格納し、渡された`keyId`と関連付けます。
`WOLFHSM_KEYID_ERASED`を`keyId`として使用すると、wolfHSMは新しい一意の`keyId`を割り当て、keyIdパラメータを通じて返します。
wolfHSMのキャッシュスロットの数は`WOLFHSM_NUM_RAMKEYS`で設定された数に制限されており、すべての鍵スロットが満杯の場合は`WH_ERROR_NOSPACE`を返します。
キャッシュとNVMの両方に存在する鍵は、NVMにバックアップされているため、より多くの鍵のためのスペースを確保するためにキャッシュから削除されます。

`wh_Client_KeyCommit`は、キャッシュされた鍵をkeyIdで指定されたキーとしてNVMに保存します。

`wh_Client_KeyEvict`は、鍵をキャッシュから削除しますが、コミットされている場合はNVMには残します。

`wh_Client_KeyExport`は、鍵の内容をHSMからクライアントに読み出します。

`wh_Client_KeyErase`は、指定された鍵をキャッシュから削除し、NVMからも消去します。

## 暗号操作

クライアントアプリケーションでwolfCryptを使用する場合、`devId`引数として`WOLFHSM_DEV_ID`を渡すことで、互換性のある暗号化操作をwolfHSMサーバーで実行できます。
ただし、wolfHSMのリモート暗号化を使用する前に、wolfHSMクライアントを初期化する必要があります。

wolfHSMがそのアルゴリズムをまだサポートしていない場合、API呼び出しは`CRYPTOCB_UNAVAILABLE`を返します。

以下に、クライアントアプリケーションがwolfHSMサーバーで`AES CBC`暗号化操作を実行する例を示します。

```c
#include "wolfhsm/client.h"
#include "wolfssl/wolfcrypt/aes.h"

whClientContext clientCtx;
whClientCfg clientCfg = { /* 設定 */ };

wh_Client_Init(&clientCtx, &clientCfg);

Aes aes;
byte key[AES_128_KEY_SIZE] = { /* AES鍵 */ };
byte iv[AES_BLOCK_SIZE] = { /* AES IV */ };

byte plainText[AES_BLOCK_SIZE] = { /* 平文 */ };
byte cipherText[AES_BLOCK_SIZE];

wc_AesInit(&aes, NULL, WOLFHSM_DEV_ID);

wc_AesSetKey(&aes, &key, AES_BLOCK_SIZE, &iv, AES_ENCRYPTION);

wc_AesCbcEncrypt(&aes, &cipherText, &plainText, sizeof(plainText));

wc_AesFree(&aes);
```

クライアント所有の鍵の代わりにHSM所有の鍵（例：HSMハードウェアキー）を使用する必要がある場合、
`wh_Client_SetKeyAes`（または他の暗号化アルゴリズム用の同様の関数）などのクライアントAPI関数を使用します。
これにより、指定されたHSMキーを後続の暗号化操作に使用するようwolfHSMに指示できます。

```c
#include "wolfhsm/client.h"
#include "wolfssl/wolfcrypt/aes.h"

whClientContext clientCtx;
whClientCfg clientCfg = { /* 設定 */ };

wh_Client_Init(&clientCtx, &clientCfg);

uint16_t keyId;
Aes aes;
byte key[AES_128_KEY_SIZE] = { /* AES鍵 */ };
byte label[WOLFHSM_NVM_LABEL_LEN] = { /* 鍵ラベル */ };
byte iv[AES_BLOCK_SIZE] = { /* AES IV */ };

byte plainText[AES_BLOCK_SIZE] = { /* 平文 */ };
byte cipherText[AES_BLOCK_SIZE];

wc_AesInit(&aes, NULL, WOLFHSM_DEV_ID);

/* IVは鍵と別に設定する必要がある */
wc_AesSetIV(&aes, iv);

/* この鍵は使用前の任意のタイミングでキャッシュできます。ここでは例として示しています */
wh_Client_KeyCache(clientCtx, 0, label, sizeof(label), key, sizeof(key), &keyId);

wh_Client_SetKeyAes(&aes, keyId);

wc_AesCbcEncrypt(&aes, &cipherText, &plainText, sizeof(plainText));

/* 鍵の削除は任意です。鍵はキャッシュまたはNVMに保存され、wolfCryptで使用できます */
wh_Client_KeyEvict(clientCtx, keyId);

wc_AesFree(&aes);
```

暗号化をクライアントのローカルで実行したい場合は、`wc_AesInit()`に`INVALID_DEVID`を渡します。

```c
wc_AesInit(&aes, NULL, INVALID_DEVID);
```

より詳しい使用方法の説明やサポートされている暗号化アルゴリズムの詳細なリストをお求めでしたら、[wolfSSLマニュアル](https://www.wolfssl.com/documentation/manuals/jp/wolfssl/)内のwolfCrypt APIリファレンスをご参照ください。

### CMAC

キャッシュされた鍵を使用するCMAC操作の場合、CMACハッシュと検証操作を1回の関数呼び出しで実行するための、wolfHSM固有の別の関数を呼び出す必要があります。
関数が呼び出されたときにクライアントが鍵を提供できる場合は、通常の`wc_AesCmacGenerate_ex`と`wc_AesCmacVerify_ex`を使用できます。
しかし、事前にキャッシュされたキーを使用するためには、`wh_Client_AesCmacGenerate`と`wh_Client_AesCmacVerify`を使用する必要があります。
ワンショットではない関数の`wc_InitCmac_ex`、`wc_CmacUpdate`、`wc_CmacFinal`は、クライアント側の鍵・事前にキャッシュされた鍵のどちらでも使用できます。
これらの関数でキャッシュされたキーを使用するには、呼び出し元は`NULL`キーパラメータを渡し、`wh_Client_SetKeyCmac`を使用して適切なkeyIdを設定する必要があります。

## AUTOSAR SHE API

(本章は後日提供予定です。)
