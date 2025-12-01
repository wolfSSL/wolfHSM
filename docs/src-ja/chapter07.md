# カスタマイズ

wolfHSMは、ビルド時のオプションやユーザー定義のコールバックを通じて複数のカスタマイズポイントを提供しています。
これにより、コアライブラリのコードを変更することなく、幅広いユースケースや環境に合わせて調整できます。
本章では、wolfHSMで利用可能なカスタマイズオプションの概要を説明します。内容は以下の通りです。

- ライブラリ設定: ライブラリの特定の機能を有効化または無効化するためのコンパイル時オプション
- DMAコールバック: クライアントのメモリに直接アクセスする前後で操作を実行するために、サーバーに登録できるカスタムコールバック
- DMAアドレス許可リスト: クライアントのアクセスを特定のメモリ領域に制限するためのサーバーの仕組み
- カスタムコールバック: デフォルトのHSM機能では対応していない特定の操作を実行するために、サーバーに登録してクライアントから呼び出すことができるカスタムコールバック

## ライブラリ設定

wolfHSMライブラリには、コンパイル時の定義を通じてオン/オフを切り替えることができる多くのビルドオプションがあります。
これらの設定マクロは、`wh_config.h`という名前の設定ヘッダーファイルで定義されることを想定しています。
このファイルはwolfHSMを使用するアプリケーションによって定義され、コンパイラのインクルードパスのディレクトリ内に配置される必要があります。

サンプルの`wh_config.h`は動作確認済みの設定として、すべてのwolfHSMポートに同梱しています。

`wh_config.h`で定義可能なwolfHSMの設定項目の完全なリストについては、[APIドキュメント](appendix01.md)をご参照ください。

## DMAコールバック

wolfHSMのダイレクトメモリアクセス（DMA）コールバック機能は、クライアントのメモリに直接アクセスする前後でカスタム操作を行うためのフックをサーバー側に提供します。
これは新しい共有メモリアーキテクチャへの移植を行う際によく必要とされます。この機能は特に、クライアントとサーバーのメモリ間の一貫性を確保するために、キャッシュの無効化やアドレス変換、その他のカスタムメモリ操作などの特定のアクションをサーバーが実行する必要がある場合に有用です。

コールバックは`wh_Server_DmaRegisterCb32()`および`wh_Server_DmaRegisterCb64()`関数を使用してサーバーに登録できます。
これによって提供されたコールバックは、サーバーコンテキストのすべてのDMA操作にバインドされます。

32ビットと64ビットのアドレスを処理するための別々のコールバック関数が必要で、これらはそれぞれ32ビットと64ビットのクライアントDMA API関数に対応します。
コールバック関数は`whServerDmaClientMem32Cb`および`whServerDmaClientMem64Cb`型で、以下のように定義しています。

```c
typedef int (*whServerDmaClientMem32Cb)(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
typedef int (*whServerDmaClientMem64Cb)(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
```

DMAコールバック関数は以下の引数を受け取ります:

- `server`: サーバーコンテキストへのポインタ
- `clientAddr`: アクセスされるクライアントのメモリアドレス
- `serverPtr`: サーバーのメモリアドレス（これもポインタ）へのポインタ。コールバックは必要な変換/再マッピングを適用した後にこれを設定します。
- `len`: 要求されたメモリ操作のバイト単位の長さ
- `oper`: 変換されたサーバーアドレスに対して実行されようとしているメモリ操作（注入ポイントについては次のセクションで説明）の種類
- `flags`: メモリ操作の追加フラグ。将来的に使用することを見越して確保している領域です。

コールバックは成功時に`WH_ERROR_OK`を、エラーが発生した場合はエラーコードを返す必要があります。
コールバックが失敗した場合、サーバーはエラーコードをクライアントに伝達させます。

### コールバックの位置

DMAコールバックは、サーバーのメモリアクセスの周りの4つの異なるポイントで行われます:

- 読み取り前: クライアントメモリからデータを読み取る前にコールバックが呼び出されます。サーバーはコールバックを使用して、アドレス変換やキャッシュの無効化など、必要な読み取り前の操作を実行する必要があります。
- 読み取り後: クライアントメモリからデータを読み取った後にコールバックが呼び出されます。サーバーはコールバックを使用して、キャッシュの同期など、必要な読み取り後の操作を実行する必要があります。
- 書き込み前: クライアントメモリにデータを書き込む前にコールバックが呼び出されます。サーバーはコールバックを使用して、アドレス変換やキャッシュの無効化など、必要な書き込み前の操作を実行する必要があります。
- 書き込み後: クライアントメモリにデータを書き込んだ後にコールバックが呼び出されます。サーバーはコールバックを使用して、キャッシュの同期など、必要な書き込み後の操作を実行する必要があります。

コールバックが呼び出されるポイントは、`oper`引数を通じてコールバックに渡されます。
具体的には、以下のいずれかの値です。

```c
typedef enum {
    WH_SERVER_DMA_OPER_PRE_READ,  /* 読み取り前の操作 */
    WH_SERVER_DMA_OPER_POST_READ, /* 読み取り後の操作 */
    WH_SERVER_DMA_OPER_PRE_WRITE, /* 書き込み前の操作 */
    WH_SERVER_DMA_OPER_POST_WRITE /* 書き込み後の操作 */
} whServerDmaOper;
```

これにより、コールバックは`oper`の値で`switch`文を使用し、実行されるメモリ操作の種類に基づいてカスタムロジックを実行できます。
以下にDMAコールバックの実装例を示します。

```c
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"

/* 32ビットクライアントアドレス用のDMAコールバック実装例 */
int myDmaCallback32(whServerContext* server, uint32_t clientAddr,
                   void** xformedCliAddr, uint32_t len,
                   whServerDmaOper oper, whServerDmaFlags flags)
{
   /* 必要に応じてクライアントアドレスをサーバーのアドレス空間に変換、例：memmap() */
   *xformedCliAddr = (void*)clientAddr; /* 変換を実行 */

   switch (oper) {
       case WH_DMA_OPER_CLIENT_READ_PRE:
           /* 読み取り前の操作をここに記述、例：キャッシュの無効化 */
           break;
       case WH_DMA_OPER_CLIENT_READ_POST:
           /* 読み取り後の操作をここに記述 */
           break;
       case WH_DMA_OPER_CLIENT_WRITE_PRE:
           /* 書き込み前の操作をここに記述 */
           break;
       case WH_DMA_OPER_CLIENT_WRITE_POST:
           /* 書き込み後の操作をここに記述、例：キャッシュのフラッシュ */
           break;
       default:
           return WH_ERROR_BADARGS;
   }

   return WH_ERROR_OK;
}
```

### コールバックの登録

コールバックは、いつでもサーバーコンテキストに登録できます。
初期化時にはサーバー設定構造体を通じて、初期化後にはコールバック登録関数を使用して実施します。

初期化時にコールバックを登録するには、コールバック関数をサーバー設定構造体内のDMA設定構造体に含める必要があります。
なお、コールバック関数の設定は任意であり、使用しないコールバックは`NULL`と設定できます。

```c
#include "wolfhsm/wh_server.h"

/* DMA32コールバックを持つサーバー設定構造体の初期化とサーバーの初期化の例 */
int main(void)
{
   whServerDmaConfig dmaCfg = {0};
   dmaCfg.dma32Cb = myDmaCallback32;


   whServerConfig serverCfg = {
       .dmaCfg = dmaCfg,

       /* 簡潔にするため、その他の設定は省略 */
   };

   whServerContext serverCtx;

   wh_Server_Init(&serverCtx, &serverCfg);

   /* サーバーアプリケーションのロジック */
}
```

初期化後にコールバックを登録する際は、以下のように関数を呼び出します。

```c
#include "wolfhsm/wh_server.h"

int main(void)
{
   whServerConfig serverCfg =  { /* サーバーの設定 */ };

   whServerContext serverCtx;

   wh_Server_Init(&serverCtx, &serverCfg);

   /* 上で定義したコールバックを登録 */
   wh_Server_DmaRegisterCb32(&serverCtx, myDmaCallback32);

   /* サーバーアプリケーションのロジック */
}
```

## DMAアドレス許可リスト

wolfHSMは、クライアントのDMAアドレスに対する「許可リスト」も公開しています。
これにより、クライアントによるアクセスを事前に設定した特定のメモリ領域に制限できます。
この機能は、サーバーが不正なアクセスを拒否するため、あるいはクライアントが安全にアクセスできるメモリにのみアクセスできるようにするために有用です。
例えば、複数のコアでそれぞれクライアントが実行されるマルチコアシステムでは、クライアントは他のクライアントのメモリ領域にアクセスできないようにすべきであり、暗号化キーなどの機密情報を含む可能性のあるサーバーメモリを読み出すこともできないようにすべきです。

ただしこの許可リスト機能は、デバイス固有のメモリ保護メカニズムの上に第二層の保護として機能することを意図しています。
よって、不正なメモリアクセスを防ぐ第一の防衛線とは考えるべきではありません。
ユーザーはアプリケーションを厳密に分離し、HSMコアと関連メモリをシステムの残りの部分から分離するために必要な、デバイス固有のメモリ保護メカニズムを設定することが不可欠です。

### 許可リストへの登録

DMAコールバックと同様に、いつでもサーバーコンテキストに登録できます。

初期化時にリストを登録するには、サーバー設定構造体内のDMA設定構造体にリストを設定する必要があります。

```c
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"

/* 許可されるメモリ領域を定義 */
const whServerDmaAddrAllowList allowList = {
   .readList = {
       {(void*)0x20001000, 0x100},  /* 0x20001000から0x200010FFまでの読み取りを許可 */
       {(void*)0x20002000, 0x200},  /* 0x20002000から0x200021FFまでの読み取りを許可 */
   },
   .writeList = {
       {(void*)0x20003000, 0x100},  /* 0x20003000から0x200030FFまでの書き込みを許可 */
       {(void*)0x20004000, 0x200},  /* 0x20004000から0x200041FFまでの書き込みを許可 */
   },
};

int main()
{
   whServerConfig config;


   whServerDmaConfig dmaCfg = {0};
   dmaCfg.allowList = &allowList;

   whServerConfig serverCfg = {
       .dmaCfg = dmaCfg,
       /* 簡潔にするため、その他の設定は省略 */
   };

   whServerContext server;

   wh_Server_Init(&server, &config);

   /* これでサーバーは許可リストで設定されました */
   /* その他のサーバー操作を実行 */

   /* 許可リストは、サーバー設定構造体にリストが存在しない場合、
    * 初期化後に以下を使用して登録することもできます。
    *
    *    wh_Server_DmaRegisterAllowList(&server, &allowList);
    */
}
```

登録後、クライアントからサーバーに要求されるすべてのDMA操作は、許可リストと照合してチェックされます。
クライアントが許可リストにないメモリ領域にアクセスしようとすると、サーバーはクライアントにエラーを返し、その操作は実行されません。

## カスタムコールバック

wolfHSMのカスタムコールバック機能により、開発者はサーバー上にカスタムコールバック関数を登録することで、ライブラリの機能を拡張できます。
これらのコールバックは、HSMが対応していない特定の操作を実行するために、クライアントから呼び出すことができます。
例えば、周辺ハードウェアの有効化や無効化、カスタムの監視や認証ルーチンの実装、追加コアのセキュアブートのステージングなどです。

### サーバー側

サーバーは、特定の操作を定義するカスタムコールバック関数を登録できます。これらの関数は`whServerCustomCb`型である必要があります。

```c
/* wh_server.h */

/* サーバーのカスタムコールバックの型定義 */
typedef int (*whServerCustomCb)(
   whServerContext* server,   /* 送信元のサーバーコンテキストを指すポインタ */
   const whMessageCustomCb_Request* req, /* クライアントからコールバックへのリクエスト */
   whMessageCustomCb_Response*      resp /* コールバックからクライアントへのレスポンス */
);
```

サーバーのカスタムコールバック関数は、サーバーのカスタムコールバックディスパッチテーブルのインデックスに対応する一意の識別子（ID）に関連付けられます。
クライアントは呼び出しを要求する際に、このIDでコールバックを参照します。

カスタムコールバックは、コールバック関数に渡される`whMessageCustomCb_Request`引数を通じて、値またはポインタ参照（共有メモリシステムで有用）によってクライアントから渡されたデータにアクセスできます。
コールバックは入力データに基づいて処理を行い、`whMessageCustomCb_Response`引数を通じてクライアントに返される出力データを生成できます。
入力/出力クライアントデータの送受信はwolfHSMによって外部で処理されるため、カスタムコールバックでこれらを処理する必要はありません。
レスポンス構造体には、クライアントに伝播させるためのエラーコードとリターンコードのフィールドも含まれています。
エラーコードはコールバックによって設定され、リターンコードはカスタムコールバックからの戻り値に設定されます。

### クライアント側

クライアントは、これらのカスタムコールバックを呼び出すためのリクエストをサーバーに送信できます。
APIは、クライアントAPIの他の関数と同様のリクエスト関数とレスポンス関数を提供します。
クライアントはカスタムリクエスト構造体のインスタンスを宣言し、カスタムデータを設定し、`wh_Client_CustomCbRequest()`を使用してサーバーに送信する必要があります。
サーバーのレスポンスは`wh_Client_CustomCbResponse()`を使用してポーリングすることができ、正常に受信された場合、レスポンスデータは出力の`whMessageCustomCb_Response()`に格納されます。

クライアントは`wh_Client_CustomCheckRegistered()`系の関数を使用して、特定のコールバックIDの登録状態を確認することもできます。
この関数は、指定されたコールバックIDがサーバーの内部コールバックテーブルに登録されているかどうかをサーバーに問い合わせます。
サーバーは登録状態を示すtrueまたはfalseで応答します。

### カスタムメッセージ

クライアントは、カスタムリクエストおよびレスポンスメッセージ構造体を通じて、カスタムコールバックにデータを渡したり、データを受け取ったりできます。
これらのカスタムリクエストおよびレスポンスメッセージは、一意のID、タイプ指示子、およびデータペイロードを含むように構成されています。
IDはサーバーのコールバックテーブルのインデックスに対応します。タイプフィールドは、データペイロードをどのように解釈すべきかをカスタムコールバックに示します。
データペイロードは固定サイズのデータバッファで、クライアントは任意の方法で使用できます。レスポンス構造体には、上述のエラーコード値が追加されています。

```c
/* カスタムサーバーコールバックへのリクエストメッセージ */
typedef struct {
   uint32_t               id;   /* 登録されたコールバックの識別子 */
   uint32_t               type; /* whMessageCustomCb_Type */
   whMessageCustomCb_Data data;
} whMessageCustomCb_Request;

/* カスタムサーバーコールバックからのレスポンスメッセージ */
typedef struct {
   uint32_t id;   /* 登録されたコールバックの識別子 */
   uint32_t type; /* whMessageCustomCb_Type */
   int32_t  rc;   /* カスタムコールバックからの戻り値。errが0でない場合は無効 */
   int32_t  err;  /* wolfHSM固有のエラー。errが0でない場合、rcは無効 */
   whMessageCustomCb_Data data;
} whMessageCustomCb_Response;
```

### カスタムデータ側の定義

カスタムデータ型は`whMessageCustomCb_Data`共用体を使用して定義することができます。
この共用体には一般的なデータ型（例：dma32、dma64）用の便利な定義済み構造体と、ユーザー定義のスキーマ用の生データバッファ（buffer）が用意されています。
クライアントはリクエストの`type`フィールドを通じて、サーバーコールバックがユニオン内のデータをどのように解釈すべきかを指示できます。
wolfHSMは最初の数個のタイプインデックスを内部使用のために予約し、残りのタイプ値はカスタムクライアントタイプで使用可能です。

### カスタムコールバックの例

ここでは、組み込みのDMAスタイルのアドレス指定タイプを使用する1つのリクエストと、カスタムユーザー定義タイプを使用する2つのリクエストの、合計3種類のクライアントリクエストを処理できるカスタムコールバックを実装します。

まず、クライアントとサーバー間で共有される共通のメッセージを定義します。

```c
/* my_custom_cb.h */

#include "wolfhsm/wh_message_customcb.h"

#define MY_CUSTOM_CB_ID 0

enum {
	MY_TYPE_A = WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START,
	MY_TYPE_B,
} myUserDefinedTypes;

typedef struct {
	int foo;
	int bar;
} myCustomCbDataA;

typedef struct {
	int noo;
	int baz;
} myCustomCbDataB;
```

サーバー側では、リクエストを処理する前に、コールバックを定義し、サーバーコンテキストに登録する必要があります。
なお、コールバックの登録は必ずしも最初のリクエストの処理前である必要はありません。いつでも行うことができます。

```c
#include "wolfhsm/wh_server.h"
#include "my_custom_cb.h"

int doWorkOnClientAddr(uint8_t* addr, uint32_t size) {
    /* タスクを実行 */
}

int doWorkWithTypeA(myCustomTypeA* typeA) {
    /* タスクを実行 */
}

int doWorkWithTypeB(myCustomTypeB* typeB) {
    /* タスクを実行 */
}

static int customServerCb(whServerContext*                 server,
                          const whMessageCustomCb_Request* req,
                          whMessageCustomCb_Response*      resp)
{
    int rc;

    resp->err = WH_ERROR_OK;

    /* DMAリクエストを検出して処理 */
    if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA32) {
        uint8_t* clientPtr = (uint8_t*)((uintptr_t)req->data.dma32.client_addr);
        size_t clientSz = req->data.dma32.client_sz;

        if (clientPtr == NULL) {
            resp->err = WH_ERROR_BADARGS;
        }
        else {
            rc = doWorkOnClientAddr(clientPtr, clientSz);
        }
    }
    else if (req->type == MY_TYPE_A) {
        myCustomCbDataA *data = (myCustomCbDataA*)((uintptr_t)req->data.data);
        rc = doWorkWithTypeA(data);
        /* 必要に応じてエラーコードを設定 */
        if (/* エラー条件 */) {
            resp->err = WH_ERROR_ABORTED;
        }
    }
    else if (req->type == MY_TYPE_B) {
        myCustomCbDataB *data = (myCustomCbDataB)((uintptr_t)req->data.data);
        rc = doWorkWithTypeB(data);
        /* 必要に応じてエラーコードを設定 */
        if (/* エラー条件 */) {
            resp->err = WH_ERROR_ABORTED;
        }
    }

    return rc;
}


int main(void) {

    whServerContext serverCtx;

    whServerConfig serverCfg = {
        /* サーバーの設定 */
    };

    wh_Server_Init(&serverCtx, &serverCfg);

    wh_Server_RegisterCustomCb(&serverCtx, MY_CUSTOM_CB_ID, customServerCb));

    /* サーバーリクエストを処理（簡略化） */
    while (1) {
        wh_Server_HandleRequestMessage(&serverCtx);
    }

}
```

これで、クライアントはカスタムコールバックの登録を確認し、リモートで呼び出すことができるようになりました。

```c
#include "wh_client.h"
#include "my_custom_cb.h"

whClientContext clientCtx;
whClientConfig  clientCfg = {
    /* クライアントの設定 */
};

whClient_Init(&clientCtx, &clientCfg);

bool isRegistered = wh_Client_CustomCheckRegistered(&client, MY_CUSTOM_CB_ID);

if (isRegistered) {
    uint8_t buffer[LARGE_SIZE] = {/* データ */};
    myCustomCbDataA typeA = {/* データ */};
    myCustomCbDataB typeB = {/* データ */};

    whMessageCustomCb_Request req = {0};
    whMessageCustomCb_Request resp = {0};

    /* 組み込みDMAタイプでカスタムリクエストを送信 */
    req.id = MY_CUSTOM_CB_ID;
    req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;
    req.data.dma32.client_addr = (uint32_t)((uintptr_t)&data);
    req.data.dma32.client_sz   = sizeof(data);
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
    /* レスポンスを使用した処理を実行 */

    /* ユーザー定義タイプでカスタムリクエストを送信 */
    memset(req, 0, sizeof(req));
    req.id = MY_CUSTOM_CB_ID;
    req.type = MY_TYPE_A;
    memcpy(&req.data.data, typeA, sizeof(typeA));
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
    /* レスポンスを使用した処理を実行 */

    /* 別のユーザー定義タイプでカスタムリクエストを送信 */
    memset(req, 0, sizeof(req));
    req.id = MY_CUSTOM_CB_ID;
    req.type = MY_TYPE_B;
    memcpy(&req.data.data, typeA, sizeof(typeB));
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
    /* レスポンスを使用した処理を実行 */
}

```

