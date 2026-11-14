// Head side of the diff fixture. Each change is commented with the kind it must be reported as.
%#include "xdr/Stellar-types.h"

namespace stellar
{

const LIMIT = 20; // const-changed
const MAX_NAME = 32;

typedef opaque Hash[32];
typedef int int32;
typedef unsigned int uint32;
typedef hyper int64;

typedef Hash OptHash;     // typedef-optional-changed
typedef opaque Blob<128>; // typedef-size-changed
typedef hyper Alias;      // typedef-changed

enum Color
{
    RED = 0,
    GREEN = 5 // enum-value-changed; BLUE: enum-member-removed
#ifdef CAP_0099_YELLOW
    ,
    YELLOW = 3 // enum-member-added, gate CAP_0099_YELLOW
#endif
};

union Shape switch (int v) // kind-changed
{
case 0:
    void;
};

struct Account
{
    int32 id;
    Hash sponsor;    // field-optional-changed
    string name<64>; // field-size-changed
    int64 balance;   // field-type-changed
    uint32 second;   // fields-reordered (first, second)
    uint32 first;
    Blob blob;
#ifdef CAP_0097_FLAGS
    uint32 flags; // field-added, gate CAP_0097_FLAGS
#else
    int32 oldFlags; // only without the feature
#endif
}; // legacy: field-removed

struct ExtV1
{
    int64 extra;
    Hash* note;
};

union Ext switch (int v)
{
case 0:
    void;
#ifdef MS_CLOSE_TIME
case 1: // arm-added (numeric), gate MS_CLOSE_TIME -> CAP-0088
    ExtV1 v1;
#endif
};

union Body switch (Color c)
{
case RED:
    int32 r;
case GREEN:
    int64 g; // arm-changed
#ifdef CAP_0099_YELLOW
case YELLOW:
    struct
    {
        int32 shade;
        Hash* tint;
    } yellow; // arm-added; anonymous struct named BodyYellow
#endif
}; // BLUE: arm-removed

union Disc switch (uint32 t) // discriminant-changed
{
case 0:
    void;
};

struct TransactionEnvelope
{
    Account acct;
    Body body;
    OptHash memoHash;
    Alias alias;
};

struct LedgerCloseMetaV1 // type-added; ungated, but only a gated arm uses it
{
    TransactionEnvelope tx;
};

union LedgerCloseMeta switch (int v)
{
case 0:
    TransactionEnvelope v0;
#ifdef CAP_0098_LCM
case 1:
    LedgerCloseMetaV1 v1;
#endif
};

struct LedgerCloseMetaBatch
{
    LedgerCloseMeta metas<>;
    Ext ext;
};

struct Unreached
{
    Disc d;
    Shape s;
};
}
