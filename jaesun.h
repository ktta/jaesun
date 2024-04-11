#ifndef JAESUN_H_INCLUDED
#define JAESUN_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

typedef struct pcObject pcObject;
typedef struct pcArray  pcArray;

enum pcType { pc_int, pc_float, pc_string, pc_ident, pc_object, pc_array };

typedef struct 
{
  enum pcType type;
  uint64_t    pos;
  union
  {
    uint64_t  intv;
    double    flov;
    char     *strv;
    pcObject *objv;
    pcArray  *arrv;
  };
} pcValue;

typedef struct  { char *name;      uint64_t   pos;
                  int   nvalues;   pcValue   *values;  } pcField;
struct pcObject { int   nfields;   pcField   *fields;  };
struct pcArray  { int   nvalues;   pcValue   *values;  };

typedef struct pcParser pcParser;

pcParser   *pcParserInit();
void        pcParserSet (pcParser *P, char *name, char *value, ...);
int         pcParserLoad(pcParser *P,char *filename, char *contents);
pcField    *pcParserFree(pcParser *P, size_t *nf);
void        pcFreeFields(int nfields, pcField *F);

void        pcGetError  (pcParser *P,char **fn, int *ln, char **estr);
void        pcGetPosData(uint64_t pos, char **fn, int *line);

void        pcCleanup();

#ifdef JAESUN_PRINT
void pcParserPrintValues(int nv, pcValue *V);
void pcParserPrintFields(int nf, pcField *F);
void pcParserPrintArray(pcArray *A);
void pcParserPrintObject(pcObject *O);
#endif

#endif

#ifdef JAESUN_IMPLEMENTATION

#include <stdlib.h>
#include <stdint.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <stdarg.h>

/**
                   File Name Records

Each file is given a number. This number is then stored in the position
field of tokens along with a line number. This allows a rough position
for reporting errors.
 **/

static struct pcfilerecord
{
  int len, size;
  char **data;
} pcFileRecord;

static int pcRecordFile(char *name)
{
  struct pcfilerecord *R;
  R= &pcFileRecord;
  if (R->len==R->size)
  {
    if (R->size) R->size+= R->size/2;
            else R->size=  256;
    R->data= realloc(R->data, R->size*sizeof(R->data[0]));
  }
  R->data[R->len]= strdup(name);
  return R->len++;
}

static void pcCleanFileRecords()
{
  struct pcfilerecord *R;
  R= &pcFileRecord;
  if (R->data)
  {
    int i;
    for(i=0;i<R->len;i++)
      free(R->data[i]);
    free(R->data);
    R->data= NULL;
  }
  R->len= R->size= 0;
}

static char* pcFileName(int number)
{
  if (number<pcFileRecord.len)
     return pcFileRecord.data[number];
  else
     return "<unknown>";
}

void pcGetPosData(uint64_t pos, char **fn, int *line)
{
  if (fn) *fn= pcFileName(pos>>32);
  if (line) *line= pos;
}

/**
lexemes:

  comment:       # comment until newline
  identifier:    [A-Za-z_][A-Za-z_0-9]*
                 "{single line string}
                 "(TAG
                 multi line string
                 goes here
                 TAG)
  integer:       octal | binary | decimal | hexadecimal
  octal:         0o[0-7]+
  binary:        0b[0-1]+
  decimal:       [0-9]+
  hexadecimal:   0x hexdigits
  hexdigits:     [0-9a-fA-F]+
  float:         decimal . decimal ([Ee] [+-]? decimal)?
  float:         hexadecimal . hexdigits ([Pp] [+-]? decimal)? 
  reference:     $identifier   
 **/

#define AVL_IMPLEMENTATION
#define AVL_PRIVATE

/***    AVL {   ***/
/**
   AVL trees. See
     http://kt8216.unixcab.org/avl/index.html
   for a discussion.

    _insert()  returns  NULL on success.
               returns  the value already stored in the tree with the
                        same key.
    _destroy() returns  the least element in the tree after removing it.
               after _destroy() returns NULL, you may simply free() the
               tree object.
 **/
#ifndef avl_h_included_20240324
#define avl_h_included_20240324

#ifdef AVL_PRIVATE
#ifdef AVL_IMPLEMENTATION
#define AVL_SCOPE static
#else
#error "AVL is imported PRIVATE but IMPLEMENTATION is not enabled"
#endif
#else
#define AVL_SCOPE
#endif

typedef struct avl avl_t;

AVL_SCOPE avl_t   *avl_new      (int (*compare)(void*, void*));
AVL_SCOPE void    *avl_find     (avl_t *T, void *key);
AVL_SCOPE void    *avl_insert   (avl_t *T, void *data);
AVL_SCOPE void    *avl_remove   (avl_t *T, void *key);
AVL_SCOPE void    *avl_destroy  (avl_t *T);

#endif

#ifdef AVL_IMPLEMENTATION
#include <stdlib.h>
typedef struct avlnode {
   struct avlnode *left, *right,*parent;
   int height;
   void *data;
} avlnode_t;

struct avl {
  avlnode_t *root;
  int (*compare)(void*,void*);
};

static avlnode_t *avl_find_node(avl_t *T, void *key)
{
   avlnode_t *n;
   n= T->root;
   while(n) {
     int u= (*T->compare)(key, n->data);
     if (u==0) return n;
     else if (u<0) n= n->left;
     else n= n->right;
   }
   return 0;
}

static int avl_HEIGHT(avlnode_t * A)
{
  if (A) return A->height;
  else return 0;
}

static void avl_calculate_height(avlnode_t *N)
{
  int hL, hR;
  hL= avl_HEIGHT(N->left);
  hR= avl_HEIGHT(N->right);
  N->height= (hL > hR ? hL : hR ) +1;
}

static void avl_replace_child_in_parent
    (avl_t* T, avlnode_t* old, avlnode_t* nw)
{
  if (old->parent)
    {
      if (old->parent->left == old)
	old->parent->left = nw;
      else
	old->parent->right = nw;
    }
  else
    {
      T->root = nw;
    }
  if (nw) nw->parent= old->parent;
}

static void avl_set_left_child(avlnode_t *P, avlnode_t *N)
{
  P->left= N; 
  if (N) N->parent= P;
}

static void avl_set_right_child(avlnode_t *P, avlnode_t *N)
{
  P->right= N; 
  if (N) N->parent= P;
}

static int avl_right_heavy(avlnode_t *A)
{
  if (!A) return 0;
  return (avl_HEIGHT(A->right)-avl_HEIGHT(A->left)) > 0;
}

static int avl_left_heavy(avlnode_t *A)
{
  if (!A) return 0;
  return (avl_HEIGHT(A->right)-avl_HEIGHT(A->left)) < 0;
}
 
static void avl_rotate_left(avl_t *T, avlnode_t *A)
{
  avlnode_t *B;
  B = A->right;
  avl_set_right_child(A, B->left);
  avl_replace_child_in_parent(T, A, B);
  avl_set_left_child(B, A);
  avl_calculate_height(A);
  avl_calculate_height(B);
}

static void avl_rotate_left_twolevels(avl_t *T, avlnode_t *A)
{
  avlnode_t *B, *C;

  B = A->right; C = B->left;
  avl_set_right_child(A, C->left);
  avl_set_left_child(B, C->right);
  avl_replace_child_in_parent(T, A, C);
  avl_set_left_child(C, A);
  avl_set_right_child(C, B);
  avl_calculate_height(A);
  avl_calculate_height(B);
  avl_calculate_height(C);
}

static void avl_rotate_right(avl_t *T, avlnode_t *A)
{
  avlnode_t *B;

  B = A->left;

  A->left = B->right;
  if (A->left) A->left->parent = A;

  B->parent = A->parent;
  avl_replace_child_in_parent(T, A, B);

  B->right = A;
  A->parent = B;

  avl_calculate_height(A);
  avl_calculate_height(B);
}

static void avl_rotate_right_twolevels(avl_t *T, avlnode_t *A)
{
  avlnode_t *B, *C;

  B = A->left;
  C = B->right;
  /* we know that B and C are non-null since
     A was left heavy and B was right heavy */

  A->left = C->right;
  if (A->left) A->left->parent = A;

  B->right = C->left;
  if (B->right) B->right->parent = B;

  C->parent = A->parent;
  avl_replace_child_in_parent(T, A, C);

  C->left = B;
  C->right = A;
  A->parent = C;
  B->parent = C;

  avl_calculate_height(A);
  avl_calculate_height(B);
  avl_calculate_height(C);
}

static void avl_rebalance(avl_t *T, avlnode_t *N)
{
  int u;
  avlnode_t *P;

  avl_calculate_height(N);

  u = avl_HEIGHT(N->left)-avl_HEIGHT(N->right);
  P = N->parent;
  if (u < -1) {
      if (avl_left_heavy(N->right)) avl_rotate_left_twolevels(T, N);
      else avl_rotate_left(T, N);
  } else if (u > 1) {
      if (avl_right_heavy(N->left)) avl_rotate_right_twolevels(T, N);
      else avl_rotate_right(T, N);
  }

  if (P) avl_rebalance(T, P);
}
 
static avlnode_t *avl_remove_max(avl_t *T,avlnode_t *N)
{
   while(N->right) N= N->right;
   avl_replace_child_in_parent(T, N, N->left);
   if (N->parent) avl_rebalance(T,N->parent);
   return N;
}

static avlnode_t *avl_remove_min(avl_t *T,avlnode_t *N)
{
   while(N->left) N= N->left;
   avl_replace_child_in_parent(T, N, N->right);
   if (N->parent) avl_rebalance(T,N->parent);
   return N;
}
static void *avl_remove_node(avl_t *T, avlnode_t *N)
{
   avlnode_t *Z;
   void *R;
   if (!N->left && !N->right) {
     avl_replace_child_in_parent(T, N, 0);
     if (N->parent) avl_rebalance(T,N->parent);
   } else {
     if (avl_left_heavy(N)) Z= avl_remove_max(T,N->left);
                       else Z= avl_remove_min(T,N->right);
     avl_replace_child_in_parent(T, N, Z);
     avl_set_left_child(Z, N->left);
     avl_set_right_child(Z, N->right);
     avl_rebalance(T,Z);
   }
   R= N->data;
   free(N);
   return R;
}

AVL_SCOPE avl_t *avl_new(int (*compare)(void*, void*))
{
  avl_t *T;
  T= malloc(sizeof(*T));
  T->root= 0;
  T->compare= compare;
  return T;
}

AVL_SCOPE void *avl_find(avl_t *T, void *key)
{
   avlnode_t *n;
   n= avl_find_node(T, key);
   if (n) return n->data;
   return 0;
}

AVL_SCOPE void* avl_insert(avl_t *T, void *data)
{
  avlnode_t *N,*P,*K,**PL;
  int R;

  N = calloc(1, sizeof(*N));
  N->data= data;
  N->height= 1;

  P = 0;
  PL= &T->root;
  K= T->root;
  while (K) {
    R= (*T->compare)(data, K->data);
    if (R<0)      { PL= &K->left; P= K; K= K->left; }
    else if (R>0) { PL= &K->right; P= K; K= K->right; }
    else          { free(N); return K->data; }
  }
  *PL= N;
  N->parent= P;
  avl_rebalance(T, N);
  return 0;
}

AVL_SCOPE void *avl_remove(avl_t *T, void *key)
{
   avlnode_t *N;
   N= avl_find_node(T,key);
   if (!N) return 0;
   return avl_remove_node(T,N);
}

AVL_SCOPE void *avl_destroy(avl_t *T)
{
   avlnode_t *N= T->root;
   if (!N) return 0;
   while(N->left) N=N->left;
   return avl_remove_node(T,N);
}

#endif

/*** } AVL  ***/ 


typedef struct lexer
{
  struct
  {
    int type;
    uint64_t pos;
    char *data;
    uint64_t intv;
    double   flov;
  } token;
  unsigned int tokbufsize, tokbuflen;   
  unsigned int fileno;

  uint64_t pos;

  char *buffer; unsigned int buffersize, bufferlen, bufferpos;
  int allocinput;

  int fd;
  unsigned char C;
  char *filename;
  int error;

  avl_t *symbols;
} pcLexer;

enum { tk_int, tk_string, tk_float, tk_ident, tk_openc, tk_closec,
                                              tk_opens, tk_closes,
                                              tk_openr, tk_closer,
                                              tk_eof,   tk_error,
                                              tk_semicolon };

typedef struct
{
  char *name;
  char *value;
} pcSymbol;

static int pcSymbolCompare(void *a, void *b)
{
  pcSymbol *A= a, *B= b;
  return strcmp(A->name, B->name);
}

static char *pcLexerLookupSymbol(pcLexer *L, char *name)
{
  pcSymbol *S, K;
  K.name= name;
  S= avl_find(L->symbols, &K);
  if (S) return S->value;
    else return "";
}

static int      pcLexerError(pcLexer *L, const char *fmt,...)
{
  va_list ap;
  int sz;
  if (L->error) return L->token.type= tk_error;
  L->error= 1;
  va_start(ap, fmt);
  sz= 1+ vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (L->tokbufsize<sz)
  {
    L->tokbufsize= sz;
    if (L->token.data) free(L->token.data);
    L->token.data= malloc(L->tokbufsize);
  }
  va_start(ap, fmt);
  vsnprintf(L->token.data, sz, fmt, ap);
  va_end(ap);
  return L->token.type= tk_error;
}

static void     pcLexerNextChar(pcLexer *L)
{
  if (L->C=='\n') L->pos++;
restart:
  if (L->bufferpos<L->bufferlen)
  {
    L->C= L->buffer[L->bufferpos++];
    return ;
  }
  if (L->fd<0)
  {
    L->C= 0;
    return ;
  }
  L->bufferpos= 0;
again:
  L->bufferlen= read(L->fd, L->buffer, L->buffersize);
  if (L->bufferlen>0) goto restart;
  if (L->bufferlen==0) 
  {
    close(L->fd);
    L->fd= -1;
    L->C= 0;
    return ;
  }
  if (errno==EINTR) goto again;
  L->C= 0;
  pcLexerError(L, "read(%s): %s", L->filename, strerror(errno));
}

static int      pcLexerIsSpaceC(unsigned char C)
{
  return (C>0 && C<=32) || (C==127);
}

static int      pcLexerIsSpace(pcLexer *L)
{
  return pcLexerIsSpaceC(L->C);
}

static void     pcLexerSkipSpace(pcLexer *L)
{
  while (pcLexerIsSpace(L)) pcLexerNextChar(L);
}

static int      pcIsIdentBeginC(unsigned char C)
{
  return (C>='a' && C<='z') ||
         (C>='A' && C<='Z') ||
         (C=='_');
}

static int      pcLexerIsIdentBegin(pcLexer *L)
{
  return pcIsIdentBeginC(L->C);
}

static int      pcLexerIsDigit2(pcLexer *L, int *V)
{
  if (L->C>='0' && L->C<='1') { if (V) *V= L->C-'0'; return 1; }
  return 0;
}

static int      pcLexerIsDigit8(pcLexer *L, int *V)
{
  if (L->C>='0' && L->C<='7') { if (V) *V= L->C-'0'; return 1; }
  return 0;
}

static int      pcIsDigit10C(unsigned char C, int *V)
{
  if (C>='0' && C<='9') { if (V) *V= C-'0'; return 1; }
  return 0;
}

static int      pcLexerIsDigit10(pcLexer *L, int *V)
{
  return pcIsDigit10C(L->C, V);
}

static int      pcLexerIsDigit16(pcLexer *L, int *V)
{
  if (L->C>='0' && L->C<='9') { if (V) *V= L->C-'0'; return 1; }
  if (L->C>='a' && L->C<='f') { if (V) *V= L->C-'a'+10; return 1; }
  if (L->C>='A' && L->C<='F') { if (V) *V= L->C-'A'+10; return 1; }
  return 0;
}

static int      pcIsIdentC(unsigned char C)
{
  return pcIsIdentBeginC(C) || pcIsDigit10C(C, NULL);
}

static int      pcLexerIsIdent(pcLexer *L)
{
  return pcIsIdentC(L->C);
}

static void     pcLexerMakeSpace(pcLexer *L, int amount)
{
  if (L->tokbuflen+amount+1<=L->tokbufsize) return ;
  L->tokbufsize += L->tokbufsize/2 + amount;
  L->token.data= realloc(L->token.data, L->tokbufsize);
}

static void     pcLexerPutChar(pcLexer *L, unsigned char C)
{
  pcLexerMakeSpace(L, 1);
  L->token.data[L->tokbuflen++]= C;
  L->token.data[L->tokbuflen]= 0;
}

static void     pcLexerCopyChar(pcLexer *L)
{
  pcLexerPutChar(L, L->C);
}

static void     pcLexerPutString(pcLexer *L, char *str, int len)
{
  if (len<0) len= strlen(str);
  if (!len) return ;
  pcLexerMakeSpace(L, len);
  memcpy(L->token.data + L->tokbuflen, str, len);
  L->tokbuflen += len;
  L->token.data[L->tokbuflen]= 0;
}

static void     pcLexerCopyNext(pcLexer *L)
{
  pcLexerCopyChar(L); 
  pcLexerNextChar(L); 
}

static void     pcLexerCopyIdent(pcLexer *L)
{
  while(pcLexerIsIdent(L)) pcLexerCopyNext(L);
}

static int      pcLexerParseIdent(pcLexer *L)
{
  L->token.type= tk_ident;
  pcLexerCopyIdent(L);
  return L->token.type;
}

static int      pcLexerParseSimple(pcLexer *L, int type)
{
  L->token.type= type;
  pcLexerNextChar(L);
  return L->token.type;
}

static int      pcLexerParseEOF(pcLexer *L)
{
  if (L->error) L->token.type= tk_error;
           else L->token.type= tk_eof;
  return L->token.type;
}

static int      pcLexerParseDollar(pcLexer *L)
{
  char *V;
  pcLexerNextChar(L);
  pcLexerCopyIdent(L);
  V= pcLexerLookupSymbol(L, L->token.data);
  L->tokbuflen= 0;
  L->token.data[0]= 0;
  pcLexerPutString(L, V, -1);
  return L->token.type= tk_string;
}

static int pcLexerCheckTagTrailer(pcLexer *L, int start)
{
  int i;
  for(i=start;L->token.data[i];i++)
    if (!pcLexerIsSpaceC((unsigned char) L->token.data[i]))
       return pcLexerError(L,"extra characters after tag");
  return 0;
}

static int      pcLexerGetLine(pcLexer *L)
{
  while(L->C!=0 && L->C!='\n') pcLexerCopyNext(L); 
  if (L->C==0) return pcLexerError(L, "unfinished line");
  pcLexerCopyNext(L);
  return 0;
}

static int      pcLexerDecodeEscape(pcLexer *L)
{
  char *inp, *o_inp, *K, *p;
  if (!strchr(L->token.data, '$')) return 0;
  o_inp= inp= strdup(L->token.data);

again:
  K= strchr(inp, '$');
  if (!K) goto put_rest;
  if (K!=inp) 
  {
    pcLexerPutString(L, inp, K-inp);
    inp= K;
  }
retry:
  for(K=inp+1;*K!=';' && *K!=0 && *K!='$';K++)   ;
  switch(*K)
  {
  case   0: break;
  case '$': pcLexerPutString(L, inp, K-inp); inp= K; goto retry;
  case ';': if (!pcIsIdentBeginC(inp[1])) goto bad_var;
            for(p=inp+2;p<K;p++) if (!pcIsIdentC(*p)) goto bad_var;
            *K= 0;
            pcLexerPutString(L, pcLexerLookupSymbol(L, inp+1), -1);
            inp= K+1;
            goto again;
  }

put_rest:
  pcLexerPutString(L, inp, -1);

done:
  free(o_inp);
  return 0;

bad_var:
  pcLexerPutString(L, inp, K-inp);
  inp= K;
  goto again;
}

static int      pcLexerUnterminatedString(pcLexer *L)
{
  return pcLexerError(L, "unterminated string");
}

static int      pcLexerParseMultiLineString(pcLexer *L, int esseq)
{
  char *tag;
  int taglen, linestart;

  pcLexerNextChar(L);   // skip the '('
  while(L->C!=0 && !pcLexerIsSpace(L)) pcLexerCopyNext(L);
  if (L->C==0)  return pcLexerUnterminatedString(L);
  pcLexerPutChar(L, ')');
  tag= strdup(L->token.data);
  L->tokbuflen= 0;
  L->token.data[0]= 0;

  if (pcLexerGetLine(L)) return L->token.type;
  if (pcLexerCheckTagTrailer(L, 0)) return L->token.type;
  L->tokbuflen= 0;
  L->token.data[0]= 0;
  taglen= strlen(tag);

  while(1)
  {
    linestart= L->tokbuflen;
    if (pcLexerGetLine(L))
    {
       free(tag); 
       return pcLexerUnterminatedString(L);
    }
    if (    L->tokbuflen-linestart>=taglen 
         && !strncmp(L->token.data+linestart, tag, taglen)) break;
  }
  free(tag);
  if (pcLexerCheckTagTrailer(L, linestart+taglen)) return L->token.type;
  L->token.data[linestart]= 0; // erase the last line containing tag..
  if (esseq) pcLexerDecodeEscape(L);
  return L->token.type;
}

static int      pcLexerParseSingleLineString(pcLexer *L, int esseq)
{
  pcLexerNextChar(L); // skip the '{'
  while(L->C!='\n' && L->C!=0 && L->C!='}') pcLexerCopyNext(L);
  if (L->C!='}') return pcLexerUnterminatedString(L);
  pcLexerNextChar(L);
  if (esseq) pcLexerDecodeEscape(L);
  return L->token.type;
}

static int      pcLexerParseString(pcLexer *L)
{
  int esseq=1;
  L->token.type= tk_string;
  pcLexerNextChar(L); // skip the quote
  if (L->C=='!') { esseq= 0; pcLexerNextChar(L); }
  switch(L->C)
  {
  case '(': return pcLexerParseMultiLineString(L, esseq);
  case '{': return pcLexerParseSingleLineString(L, esseq);
  }
  return pcLexerError(L,"unknown string specifier");
}

static int      pcLexerIsDigit(pcLexer *L, int base, int *R)
{
  switch(base)
  {
  case  2: return pcLexerIsDigit2(L, R);
  case  8: return pcLexerIsDigit8(L, R);
  case 10: return pcLexerIsDigit10(L, R);
  case 16: return pcLexerIsDigit16(L, R);
  }
  return 1;
}

static int      pcLexerParseDigits(pcLexer *L, uint64_t *R, int base, int *Rd)
{
  int nd, d;
  uint64_t V= 0;
  
  nd= 0;
  while(1)
  {
    if (pcLexerIsDigit(L, base, &d))
    {
      V= V*base + d;
      nd++;
      pcLexerNextChar(L);
    }
    else if (L->C=='_') 
    {
      pcLexerNextChar(L);
    }
    else
    {
      break;
    }
  }
  *R= V;
  *Rd= nd;
  if (nd==0) return pcLexerError(L, "bad integer");
        else return 0;
}

static int      pcLexerParseInteger(pcLexer *L, uint64_t *R, int *Rbase)
{
  int base, nd;
  if (L->C=='0')
  {
    pcLexerNextChar(L);
    switch(L->C)
    {
    case 'b': case 'B': base= 2;  pcLexerNextChar(L); break;
    case 'o': case 'O': base= 8;  pcLexerNextChar(L); break;
    case 'x': case 'X': base= 16; pcLexerNextChar(L); break;
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    case '8': case '9': base= 10; pcLexerNextChar(L); break;
               default: *Rbase= 10; *R= 0; return 0;
    }
  }
  else
  {
    base= 10; 
  }
  *Rbase= base;
  if (pcLexerParseDigits(L, R, base, &nd)) return 1;
  return 0;
}

static int      pcLexerParseNumber(pcLexer *L)
{
  int fneg= 0, ffraction= 0, fexp=0;
  uint64_t V, F, T;
  int E;
  int base, nfd, ned; // nFractionDigits   nExponentDigits

  if (L->C=='-') { pcLexerNextChar(L); fneg= 1; }
  if (pcLexerParseInteger(L, &V, &base)) return L->token.type;
  if (base==2 || base==8) goto intonly;

  if (L->C=='.')
  {
    pcLexerNextChar(L);
    ffraction= 1;
    if (pcLexerParseDigits(L, &F, base, &nfd)) return L->token.type;
  }
  if (    (base==16 && (L->C=='P' || L->C=='p'))
       || (base==10 && (L->C=='E' || L->C=='e')) )
  {
    int fexpneg= 0;
    pcLexerNextChar(L);
    fexp= 1;
         if (L->C=='-')      { fexpneg= 1; pcLexerNextChar(L); }
    else if (L->C=='+')      {             pcLexerNextChar(L); }
    if (pcLexerParseDigits(L, &T, 10, &ned)) return L->token.type;
    E= T;
    if (fexpneg) E= -E;
  }

  if (!ffraction && !fexp) goto intonly;
  L->token.flov= V;
  if (ffraction) L->token.flov +=  (double) F / pow(base, nfd);
  if (fexp)      L->token.flov *=  pow( base==16 ? 2 : 10, E);
  if (fneg)      L->token.flov  = -L->token.flov;
  return L->token.type= tk_float;
  
intonly:
  L->token.intv= V;
  if (fneg) L->token.intv= -L->token.intv;
  return L->token.type=tk_int;
}

static int      pcLexerGet(pcLexer *L)
{
  int dummy;
again:
  L->tokbuflen= 0;
  pcLexerSkipSpace(L);
  L->token.pos= L->pos;
  switch(L->C)
  {
  case   0: return pcLexerParseEOF(L); 
  case '{': return pcLexerParseSimple(L,tk_openc);
  case '}': return pcLexerParseSimple(L,tk_closec);
  case '(': return pcLexerParseSimple(L,tk_openr);
  case ')': return pcLexerParseSimple(L,tk_closer);
  case '[': return pcLexerParseSimple(L,tk_opens);
  case ']': return pcLexerParseSimple(L,tk_closes);
  case ';': return pcLexerParseSimple(L,tk_semicolon);
  case '$': return pcLexerParseDollar(L); 
  case '"': return pcLexerParseString(L);
  case '#': if (pcLexerGetLine(L)) return L->token.type;
            goto again;
  }
  if (pcLexerIsIdentBegin(L)) return pcLexerParseIdent(L);
  if (L->C=='-' || pcLexerIsDigit10(L,NULL)) return pcLexerParseNumber(L);
  return pcLexerError(L,  "unknown character");
}

static pcLexer *pcLexerInit(char *filename, char *contents, avl_t *symbols)
{
  pcLexer *L;
  L= calloc(1,sizeof(*L));
  L->filename= strdup(filename);
  L->pos= (uint64_t) pcRecordFile(filename) << 32;
  L->pos++;
  L->symbols= symbols;
  if (contents)
  {
    L->buffer= contents;
    L->bufferlen= strlen(contents);
    L->buffersize= L->bufferlen;
  }
  else
  {
    L->buffersize= 1024;
    L->buffer= malloc(L->buffersize);
    L->allocinput= 1;
  }
  L->tokbufsize= 1024;
  L->token.data= malloc(L->tokbufsize);

  if (!contents)
  {
    L->fd= open(filename, O_RDONLY);
    if (L->fd<0)
       pcLexerError(L,"open(%s): %s", filename, strerror(errno)); 
  }
  pcLexerNextChar(L);
  return L;
}

static pcLexer *pcLexerFree(pcLexer *L)
{
  free(L->filename);
  if (L->allocinput) free(L->buffer);
  free(L->token.data);
  if (L->fd>=0) close(L->fd);
  L->fd= -1;
  free(L);
  return NULL;
}

#ifdef JAESUN_LEXER_TEST

int main(int argc, char **argv)
{
  pcLexer *L;
  char *fn; int ln;
  int q=0;
  L= pcLexerInit(argv[1], NULL, NULL);
  while(!q)
  switch(pcLexerGet(L))
  {
  case tk_int: printf("int(%d)\n", (int) L->token.intv); break;
  case tk_float: printf("float(%g)\n", L->token.flov); break;
  case tk_string: printf("string(%s)\n", L->token.data);  break;
  case tk_ident: printf("ident(%s)\n", L->token.data); break;
  case tk_openc: printf("open-c\n"); break;
  case tk_closec: printf("close-c\n"); break;
  case tk_opens: printf("open-s\n"); break;
  case tk_closes: printf("close-s\n"); break;
  case tk_openr: printf("open-r\n"); break;
  case tk_closer: printf("close-r\n"); break;
  case tk_semicolon: printf("semicolon\n"); break;
  case tk_eof: printf("eof\n"); q= 1; break;
  case tk_error: 
    pcGetPosData(L->token.pos, &fn, &ln);
    printf("%s:%d: %s\n", fn, ln, L->token.data);
    q= 1;
    break;
  default: printf("unknown %d\n", L->token.type); q= 1; 
  }

  pcLexerFree(L);
  return 0;
}
#endif

#define RELAPATH_PRIVATE
#define RELAPATH_IMPLEMENTATION

/*** RELAPATH { ***/ 
#ifndef relapath_h_included
#define relapath_h_included

#ifdef RELAPATH_PRIVATE
#ifdef RELAPATH_IMPLEMENTATION
#define RELAPATH_SCOPE static
#else
#error "RELAPATH imported PRIVATE but IMPLEMENTATION is disabled"
#endif
#else
#define RELAPATH_SCOPE
#endif

RELAPATH_SCOPE char *path_relative(char *fn, char *ref);
#endif
#ifdef RELAPATH_IMPLEMENTATION

#include <string.h>
#include <stdlib.h>

#ifdef RELAPATH_SELF_TEST
#include <stdio.h>
#endif

RELAPATH_SCOPE char *path_relative(char *fn, char *ref)
{
  char *dir;
  char *R, *K, *p;
  int ld, lf;

  if (*fn=='/') return strdup(fn);

   /** get the directory part from ref **/
  K= strrchr(ref, '/');
  if (!K) return strdup(fn);
  dir= strdup(ref);
  dir[K-ref+1]= 0;

   /** combine directory and filename **/
  ld= strlen(dir);
  lf= strlen(fn);
  R= malloc(ld+lf+1);
  memcpy(R, dir, ld);
  memcpy(R+ld, fn, lf);
  R[ld+lf]= 0;
  fn= R;
  free(dir);

  while ((K= strstr(fn, "//")))  memmove(K, K+1, strlen(K+1)+1); 
  while ((K= strstr(fn,"/./")))  memmove(K, K+2, strlen(K+2)+1); 
  while ((K= strstr(fn, "/../")))
  {
    if (K==fn) { p= K; }
          else { for(p=K-1;p>=fn && *p!='/';p--) ; 
                 if (p<fn) { p++; K++; }             } // SIDENOTE1
    memmove(p, K+3, strlen(K+3)+1);
  }
  return fn;
}

/**

SIDENOTE1: the above code was actually like this:

    if (p<fn)       // we have   something/../bar  -> bar
      memmove(fn, K+4, strlen(K+4)+1);
    else
      memmove(p, K+3, strlen(K+3)+1);
     // we have     foo/bar/../baz   -> foo/baz
     //      or        /foo/../bar   -> /bar

we know that   p=fn-1 if there is no '/' before K, so if we increment
p, we will get fn. if we also increment K, we will get K+4 as the argument
to memmove. therefore, we can do 

   if (p<fn) { p++; K++; }
   memmove(p, K+3, strlen(K+3)+1);

**/

#endif

#ifdef RELAPATH_SELF_TEST
int main(int argc,char** argv)                                                  
{                                                                               
  printf("REL(%s,%s)=(%s)\n", argv[1], argv[2],                                 
                     path_relative(argv[1],argv[2]));                           
  return 0;                                                                     
}                        
#endif
/*** } RELAPATH  ***/ 

#define OBUF_PRIVATE

/*** OBUF { ***/

#ifndef obuf_h_included
#define obuf_h_included
#include <stddef.h>

#ifdef OBUF_PRIVATE
#ifndef OBUF_IMPLEMENTATION
#define OBUF_IMPLEMENTATION
#endif
#define OBUF_SCOPE static
#else
#define OBUF_SCOPE
#endif

typedef struct obuf obuf_t;

OBUF_SCOPE obuf_t   *obuf_new     (size_t eltsize, size_t blksize);
OBUF_SCOPE void      obuf_free    (obuf_t *B);
OBUF_SCOPE void     *obuf_collect (obuf_t *B,      size_t *Rl,  int destroy);
OBUF_SCOPE void      obuf_put     (obuf_t *B,      void *D);
OBUF_SCOPE void      obuf_tailput (obuf_t *H,      obuf_t *T);
#endif

#ifdef  OBUF_IMPLEMENTATION
#include <stdlib.h>
#include <string.h>


struct obuf_node { 
  struct obuf_node *next;
  size_t len;
  unsigned char data[1];
};

struct obuf {
  struct obuf_node *first, *last;
  size_t blksize, eltsize;
};

OBUF_SCOPE obuf_t *obuf_new(size_t eltsize, size_t blksize)
{
  obuf_t *B;
  B= malloc(sizeof(*B));
  B->first= B->last= NULL;
  B->eltsize= eltsize;
  B->blksize= blksize;
  return B;
}

OBUF_SCOPE void obuf_free(obuf_t *B)
{
  struct obuf_node *P,*N;
  for(P=B->first;P;P=N)
  {
    N= P->next;
    free(P);
  }
  free(B);
}

OBUF_SCOPE void* obuf_collect(obuf_t *B, size_t *Rl, int destroy)
{
  size_t S;
  struct obuf_node *P;
  unsigned char *R;
  size_t es;

  S= 0;
  R= NULL;
  for(P=B->first;P;P=P->next) S+= P->len;
  if (S==0) goto done; 

  es= B->eltsize;
  R= malloc(S*es);
  S= 0;
  for(P=B->first;P;P=P->next)
  {
    memcpy(R+S*es, P->data, P->len*es);
    S+= P->len;
  }

done:
  if (Rl) *Rl= S;
  if (destroy) obuf_free(B);
  return R;
}

OBUF_SCOPE void obuf_put(obuf_t *B, void *d)
{
  struct obuf_node *P;
  size_t es;
  es= B->eltsize;
  P= B->last;
  if (!P || P->len==B->blksize)
  {
    P= malloc(sizeof(*P)+B->blksize*es-1);
    P->len= 0;
    P->next= NULL;
    if (B->last) { B->last->next= P; B->last= P; }
            else { B->last= B->first= P; }
  }
  memcpy(P->data+P->len*es, d, es);
  P->len++;
}

OBUF_SCOPE void      obuf_tailput (obuf_t *H,      obuf_t *T)
{
  if (!T->first) return ;
  if (!H->first)
  {
    H->first= T->first;
    H->last= T->last;
  } 
  else
  {
    H->last->next= T->first;
    H->last=  T->last;
  }
  T->first= T->last= NULL;
}

#endif
/*** } OBUF ***/

struct pcParser {
  pcLexer *lexer;
  obuf_t  *fieldbuf;
  uint64_t errorpos;
  char    *error;
  avl_t   *symbols;
};


static void        pcFreeArray(pcArray *A);
static void        pcFreeObject(pcObject *A);
static pcObject   *pcParseObject(pcParser *P,int endtok);
static pcArray    *pcParseArray(pcParser *P);


static int  pcPropagateError(pcParser *P)
{
  if (P->error) return 1;
  P->errorpos= P->lexer->token.pos;
  P->error= strdup(P->lexer->token.data);
  return 1;
}

static int  pcParseErrorPV
    (pcParser *P, uint64_t pos, const char *fmt, va_list ap)
{
  va_list cv;
  int sz;
  if (P->error) return 1;
  if (P->lexer->token.type==tk_error) 
     return pcPropagateError(P);
  P->errorpos= pos;
  va_copy(cv,ap);
  sz= vsnprintf(NULL, 0, fmt, cv) + 1;
  va_end(cv);
  P->error= malloc(sz);
  vsnprintf(P->error, sz, fmt, ap);
  return 1;
}

static int  pcParseErrorP(pcParser *P, uint64_t pos, const char *fmt, ...)
{
  va_list ap;
  va_start(ap,fmt);
  pcParseErrorPV(P, pos, fmt, ap);
  va_end(ap);
  return 1;
}

static int  pcParseError(pcParser *P, const char *fmt, ...)
{
  va_list ap;
  va_start(ap,fmt);
  pcParseErrorPV(P, P->lexer->token.pos, fmt, ap);
  va_end(ap);
  return 1;
}

void        pcGetError(pcParser *P,char **fn, int *ln, char **estr)
{
  if (P->error)
  {
    pcGetPosData(P->errorpos, fn, ln);
    if (estr) *estr= P->error;
  }
  else
  {
    if (fn) *fn= "internal"; 
    if (ln) *ln= 1;
    if (estr) *estr= "requested non-existant error description";
  }
}

static void pcFreeValue(pcValue *V)
{
  switch(V->type)
  {
  case pc_int:
  case pc_float:    break;
  case pc_string:
  case pc_ident:    free(V->strv);         break;
  case pc_object:   pcFreeObject(V->objv); break;
  case pc_array:    pcFreeArray(V->arrv);  break;
  }
}

static void pcFreeValues(int nv, pcValue *V)
{
  int i;
  for(i=0;i<nv;i++) pcFreeValue(V+i);
  free(V);
}

static void pcFreeField(pcField *F)
{
  free(F->name);
  pcFreeValues(F->nvalues, F->values);
}

void pcFreeFields(int nfields, pcField *F)
{
  int i;
  for(i=0;i<nfields;i++) pcFreeField(F+i);
  free(F);
}

static void pcFreeArray(pcArray *A)
{
  pcFreeValues(A->nvalues, A->values);
  free(A);
}

static void pcFreeObject(pcObject *O)
{
  pcFreeFields(O->nfields, O->fields);
  free(O);
}

static int    pcParseStringValue(pcParser *P, pcValue *V, int type)
{
  V->type= type;
  V->strv= strdup(P->lexer->token.data);
  pcLexerGet(P->lexer);
  return 0;
}

static int    pcParseValue(pcParser *P, pcValue *V)
{
  pcLexer *L;
  L= P->lexer;
  V->pos= P->lexer->token.pos;
  switch(P->lexer->token.type)
  {
  case tk_openc:  V->type= pc_object;  pcLexerGet(L);
                  V->objv= pcParseObject(P, tk_closec);
                  if (!V->objv) return 1;
                  break;
  case tk_opens:  V->type= pc_array;   pcLexerGet(L);
                  V->arrv= pcParseArray(P);
                  if (!V->arrv) return 1;
                  break;
  case tk_int:    V->type= pc_int;   V->intv= L->token.intv; break;
  case tk_float:  V->type= pc_float; V->flov= L->token.flov; break;
  case tk_string: return pcParseStringValue(P, V, pc_string);
  case tk_ident:  return pcParseStringValue(P, V, pc_ident);
  case tk_error:  return pcPropagateError(P);
  default:        return pcParseError(P, "unrecognized value token");
  }
  pcLexerGet(L);
  return 0;
}

static int    pcParseField(pcParser *P, pcField *F)
{
  pcLexer  *L;
  obuf_t   *B;
  size_t    sz;
  pcValue   V;
  int       fail;

  L= P->lexer;
  if (L->token.type!=tk_ident) 
     return pcParseError(P, "identifier expected at the head of declaration");

  B= obuf_new(sizeof(pcValue), 64);
  F->name= strdup(L->token.data);
  F->pos= L->token.pos;
  pcLexerGet(L);
  fail= 0;
  while(!fail && L->token.type!=tk_semicolon)
    if (pcParseValue(P, &V)) fail= 1;
                        else obuf_put(B, &V);
  F->values= obuf_collect(B, &sz, 1);
  F->nvalues= sz;

  if (fail) { pcFreeField(F);
              return 1; }
  pcLexerGet(L);
  return 0;
}

static int pcInvalidInclude(pcParser *P, uint64_t pos)
{
  return pcParseErrorP(P, pos, "invalid include directive");
}

static int pcParserIncludeSingle(pcParser *P, pcValue *V)
{
  char *path;
  int R;
  if (V->type!=pc_string) return pcInvalidInclude(P, V->pos);
  path= path_relative(V->strv, P->lexer->filename);
  R= pcParserLoad(P, path, NULL);
  free(path);
  return R;
}

static int         pcParserInclude(pcParser *P, pcField *F)
{
  int i, R;
  pcValue *V;
  R= 0;
  if (F->nvalues==0) R= pcInvalidInclude(P, F->pos);
  for(i=0;!R && i<F->nvalues;i++) R= pcParserIncludeSingle(P, F->values+i);
  pcFreeField(F);
  return R;
}

static int         pcParseFields(pcParser *P, int endtok, obuf_t *B)
{
  pcField     F;
  while(P->lexer->token.type!=endtok)
  {
    if (pcParseField(P, &F)) return 1;
    if (!strcmp(F.name, "include"))
    {
      if (pcParserInclude(P, &F)) return 1;
      continue;
    }
  //  if (!strcmp(F.name, "if"))      { /* do something */ }
    obuf_put(B, &F);
  }
  return 0;
}

static pcObject   *pcParseObject(pcParser *P,int endtok)
{
  pcObject   *O;
  obuf_t     *B;
  size_t      sz;
  int         fail;

  O= calloc(1,sizeof(*O));
  B= obuf_new( sizeof(pcField), 64 );
  fail= pcParseFields(P, endtok, B);
  O->fields= obuf_collect(B, &sz, 1);
  O->nfields= sz;
  if (fail) 
  {
    pcFreeObject(O);
    O= NULL;
  }
  return O;
}

static pcArray *pcParseArray(pcParser *P)
{
  pcArray   *A;
  int        fail;
  obuf_t    *B;
  pcValue    V;
  size_t     sz;

  fail= 0;
  A= calloc(1,sizeof(*A));
  B= obuf_new( sizeof(pcValue), 64 );
  while(P->lexer->token.type!=tk_closes)
  {
    if (pcParseValue(P, &V)) { fail= 1; break; }   
    obuf_put(B, &V);
  }
  A->values= obuf_collect(B, &sz, 1);
  A->nvalues= sz;
  if (fail)
  {
    pcFreeArray(A);
    A= NULL;
  } 
  return A;
}

static void    pcParserSetSingle(pcParser *P, char *name, char *value)
{
  pcSymbol *S;
  S= malloc(sizeof(*S));
  S->name= strdup(name);
  S->value= strdup(value);
  avl_insert(P->symbols, S);
}

void           pcParserSet(pcParser* P, char *name, char *value, ...)
{
  va_list ap;
  pcParserSetSingle(P, name, value);
  va_start(ap, value);
  while((name=va_arg(ap,char*)))
    pcParserSetSingle(P, name, va_arg(ap,char*));
  va_end(ap);
}

pcParser      *pcParserInit()
{
  pcParser *P;
  P= calloc(1, sizeof(*P));
  P->fieldbuf= obuf_new( sizeof(pcField), 64 );
  P->symbols= avl_new( pcSymbolCompare );
  pcParserSet(P, "o", "{", "c", "}", "n", "\n", "t", "\t", "q", "\"",
                 "d", "$", "s", ";", NULL);
  return P;
}


int            pcParserLoad(pcParser *P,char *filename, char *contents)
{
  int R;
  pcLexer *Lstore;
  obuf_t  *bufstore;

  bufstore= P->fieldbuf;
  P->fieldbuf= obuf_new( sizeof(pcField), 64 );
  
  Lstore= P->lexer;
  P->lexer= pcLexerInit(filename, contents, P->symbols);
  pcLexerGet(P->lexer);

  R= pcParseFields(P, tk_eof, P->fieldbuf);

  pcLexerFree(P->lexer);
  P->lexer= Lstore;

  if (R)
  {
    pcField *F;
    size_t sz;
    F= obuf_collect(P->fieldbuf, &sz, 1);
    pcFreeFields(sz, F);
  }
  else
  {
    obuf_tailput(bufstore, P->fieldbuf);
    free(P->fieldbuf);
  }
  P->fieldbuf= bufstore;

  return R;
}

pcField      *pcParserFree(pcParser *P, size_t *nf)
{
  pcField *R;
  pcSymbol *S;
  R= obuf_collect(P->fieldbuf, nf, 1);
  if (P->lexer) pcLexerFree(P->lexer);
  while( (S=avl_destroy(P->symbols)) )
  {
    free(S->name);
    free(S->value);
    free(S);
  }
  free(P->symbols);
  free(P);
  return R;
}

void        pcCleanup()
{
  pcCleanFileRecords();
}
#endif


#ifdef  JAESUN_PARSER_TEST
#define JAESUN_PRINT
#endif

#ifdef JAESUN_PRINT
void pcParserPrintArray(pcArray *A);
void pcParserPrintObject(pcObject *O);

static void pcParserPrintValue(pcValue *V)
{
  switch(V->type)
  {
  case pc_int:      printf("%ld", V->intv); break;
  case pc_float:    printf("%g", V->flov); break;
  case pc_string:   
  case pc_ident:    printf("%s", V->strv); break;
  case pc_object:   pcParserPrintObject(V->objv); break;
  case pc_array:    pcParserPrintArray(V->arrv);  break;
  }
}

void pcParserPrintValues(int nv, pcValue *V)
{
  int i;
  for(i=0;i<nv;i++) {printf(" "); pcParserPrintValue(V+i); }
}

static void pcParserPrintField(pcField *F)
{
  printf("%s: ", F->name);
  pcParserPrintValues(F->nvalues, F->values);
  printf("\n");
}

void pcParserPrintFields(int nf, pcField *F)
{
  int i;
  for(i=0;i<nf;i++) pcParserPrintField(F+i);
}

void pcParserPrintObject(pcObject *O)
{
  printf("{\n");
  pcParserPrintFields(O->nfields, O->fields);
  printf("}\n");
}

void pcParserPrintArray(pcArray *A)
{
  printf("[\n");
  pcParserPrintValues(A->nvalues, A->values);
  printf("\n]\n");
}
#endif

#ifdef JAESUN_PARSER_TEST
int main(int argc, char **argv)
{
  pcParser *P;
  size_t i, nf;
  pcField *F;

  P= pcParserInit();
  if (pcParserLoad(P, argv[1], NULL))
  {
    char *fn, *estr; int ln;
    pcGetError(P, &fn, &ln, &estr);
    printf("%s:%d: %s\n", fn, ln, estr);
  }

  F= pcParserFree(P, &nf);
  pcParserPrintFields(nf, F);
  pcFreeFields(nf, F);
  pcCleanup();
  return 0;
}
#endif

