# jaesun
Jaesun Data Specification Language
----------------------------------

This is a language which serves a role similar to JSON. Unlike JSON, it
provides file inclusion and conditional evaluation facilities.

A Jaesun file consists of data declarations. Each declaration starts with
an identifier, followed by zero or more values and ends with a semicolon.

An identifier follows the same rules used in C, it starts with a letter,
followed by zero or more letters or digits. The underscore character is
considered a letter in this context. No special meaning is assigned to
identifiers. They are passed as-is to the user.

Values can be of type identifier, integer, floating point, string, array
or object.

Integers can be written in binary, octal, decimal or hexadecimal bases.
Underscore characters may be used to group digits together for long 
constants. Integers may also be prefixed with a minus sign to represent
negative numbers. However, this sign must immediately be followed by digits.
It's not a unary operator as it is in programming languages, but part of
the number specification.

A decimal number is just written as a sequence of decimal digits. A leading
zero has no special meaning.

Numbers in other bases start with the digit 0 which is followed by the 
base specifier and digits. As a base specifier,
  'b' is used for binary,
  'o' for octal and
  'x' for hexadecimal.
Uppercase letters may also be used. 

Floating point numbers consist of an integer followed by a fraction and/or
exponent. Floating point numbers can be written only in base 10 and 16.
These follow the conventions used in C, except that a number can't start
with a dot. It has to have at least one integer digit, which could just as
well be 0.

Strings can be single line or multi-line with optional escape sequence 
decoding. A single line string starts with the "{ characters and continues
until the next } character. The program doesn't try to balance nested {}
pairs.

A multiline string starts with a tag and ends at the line where the tag
string occurs at the start of the line. For instance:

"(EOS
This kind of string may
span multiple lines. Escape
sequence decoding is still
available.
EOS)

Here, "( and ) markers are fixed, but the tag EOS could be replaced by
any string which doesn't contain whitespace characters.

In order to disable escape encoding, you may put a ! between the " and { or (
characters. Escape sequences are:

  $o;     {
  $c;     }
  $n;     newline
  $t;     tab
  $q;     "
  $d;     $
  $s;     ;
  $var;   value of var

Arrays are sequences of values surrounded by [] pairs. Types of the values
within arrays don't have to match, enforcing such things is left to the user.

Objects are collections of data declarations. Like data declarations at the
file level, these data declarations also have to start with identifiers.
Data declarations within objects are called 'fields'. An object starts with
a { and ends at the matching } character. 

Variables
---------

The input file can also contain references to variables. These are defined
by the user of the library and the references are resolved as soon as they
are seen by the parser. An undefined variable expands to the empty string.

A variable reference consists of a dollar sign followed by a variable name,
which must be valid identifier. Within a string literal, variables are still
recognized but the reference must end with a semicolon.

Here are some examples:

include "{$platform;/system.init};
reference $cool refers to variable cool;

As a matter of fact, escape sequences are also implemented as such variables.
You could override their definitions if needed.

Including Other Input Files
---------------------------

The include directive may be used for this purpose. It starts with the
identifier 'include' and is followed by one or more strings, which are
interpreted as relative paths to the current file. The directive shall
be terminated by a semicolon as is the case for all other directives.

Library Interface
-----------------

The pcParser is the main object. The following functions can be used to
interact with one:
 
pcParser      *pcParserInit ();
int            pcParserLoad (pcParser *P, char *filename, char *contents);
pcField       *pcParserFree (pcParser *P, size_t *nf);

Load() loads the given file. If contents is not NULL, then the file is not
opened, instead the given contents are used. In this case, the file name is
just used as an identifier to be used for error messages and include path
handling.

After you're done with the pcField objects, you may free them all using:

void           pcFreeFields(int nfields, pcField *F);

This also frees the pointer F. If you want to have a fully clean slate
before exiting, you may call:

void           pcCleanup();

This cleans up the file registry, which is the only global variable in
the whole module. After calling this function, pcGetPosData() described
below is no longer useful.

Error Handling
--------------

If Load() returns non-zero, there was an error while procesing the file.
You may access the details of this error using:
                                                                       
void        pcGetError  (pcParser *P,char **fn, int *ln, char **estr);          

where fn is the storage for filename, ln is for line number and estr is for
error string.

All values and fields contain position information. After a successful
parse, if you want to generate error or warning messages, you may use
the following function to access position data.

void        pcGetPosData(uint64_t pos, char **fn, int *line); 


Simpler Usage
-------------

If all you want is a simple parser with no advanced features, you may
use the one-shot function:

char         *pcParseSingleFile(char *filename, char *contents, 
                                pcField **Rfields, size_t *Rnfields);

The return value is NULL on success but an error string in case of errors.

Advanced Functionality
----------------------

You may use variables to control the output of the parser as defined above.
Within the code, you may use the following function to set values for 
variables. 

void           pcParserSet(pcParser *P, char *name, char *value, ...);

Variables can have only string values.

You can set multiple variables using Set(). You must always terminate the
argument list with a NULL.

void           pcSetLookup(pcParser *P,
                           char (*lookup)(void *,char*), 
                           void *ctx);

This sets up the lookup function for files. If the input to pcParser doesn't
live on the file system but some other medium, you may use this function
to access the files. The first argument to lookup_func is 'ctx' passed to
SetLookup(). The second argument is the name of the file. This function
should return the contents of the requested file if it exists within its
system. Otherwise it shall return NULL and the parser will fail.

Things to Do
-------------

Expressions. An expression is a sequence of values and operators surrounded
by a () pair. It's parsed according to operator precedence rules and may 
contain subexpressions which are grouped by () pairs. This will enable me
to implement the 'if' declaration.

if ($android || $linux) {
  this is nice;
};

Expressions should also be returned to the user. For instance,

 func y  (x*x+2);

should parse a struct with type pc_expr.

Conditional declarations. 

  if cond { body }
  elif cond { body }
  ..
  elif cond { body }
  else { body };

The above mentioned lookup functionality.

Error handling. Parse/lex errors are detected but the error
messages aren't quite explanatory. A stack of unclosed parenthesis
should be implemented. 

The Field parser should check whether the next token is a } or EOF.
In this case a missing semicolon error should be given.

Let's classify errors:
 - error in a lexeme, such as a malformed number etc.
 - missing quote/tag for a string
 - missing }
 - missing ;
 - bad input character
 - bad declaration start
 - characters beyond multiline tags

Verifier. Just like XML has XSD, we can have a format description file.
After running the input thru this, the user doesn't have to check for
errors himself, at least syntactically.

so, we can have:

object <name> { <field>* };
topfield <field desc>;

Error handling. We can define errors to be fatal using:

void  pcErrorsFatal(pcParser *P, int fatal);

if fatal is set, then errors will be fatal.

void  pcErrorOutput(pcParser *P, FILE *out);

if out is set then errors will be printed to 'out'.
by default both of these are unset.
