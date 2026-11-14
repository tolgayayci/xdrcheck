// Base side of the diff fixture: one definition per change kind the head side makes.
%#include "xdr/Stellar-types.h"

namespace stellar
{

const LIMIT = 10;
const MAX_NAME = 32;

typedef opaque Hash[32];
typedef int int32;
typedef unsigned int uint32;
typedef hyper int64;

typedef Hash* OptHash;    /* becomes non-optional: typedef-optional-changed */
typedef opaque Blob<64>;  // bound grows: typedef-size-changed
typedef int Alias;        // becomes hyper: typedef-changed

enum Color
{
    RED = 0,
    GREEN = 1,
    BLUE = 2
};

struct Removed
{
    int x;
};

struct Shape
{
    int a;
};

struct Account
{
    int32 id;
    Hash* sponsor;
    string name<MAX_NAME>;
    int32 balance;
    int32 legacy;
    uint32 first;
    uint32 second;
    Blob blob;
};

union Ext switch (int v)
{
case 0:
    void;
};

union Body switch (Color c)
{
case RED:
    int32 r;
case GREEN:
    Hash g;
case BLUE:
    void;
};

union Disc switch (int32 t)
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

union LedgerCloseMeta switch (int v)
{
case 0:
    TransactionEnvelope v0;
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
    Removed r;
};
}
