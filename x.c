/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* Badly Coded BASIC (BCBASIC), a product of Badly Coded, Inc. */

/* This is an example insecure program for CSci 4271 only: don't copy
   code from here to any program that is supposed to work
   correctly! */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* BCBASIC standardizes on 64-bit signed integers for integer values
   in the language, and unsigned 64-bit integers for line numbers, so
   it depends on the int64_t and uint64_t types. At the moment the
   code also asssumes in the standard library interfaces it uses that
   "long" and "unsigned long" are sufficient to hold these. */
#include <stdint.h>

/* This header file is from C11, but it only affects compiler warnings
   so you could disable it if it's a portability problem. */
#include <stdnoreturn.h>

/* Most of this program would be portable to non-Unix C environments,
   but we use the stat() system call to check the size of the input
   program before reading it. */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Compute the smaller (resp., larger) of two values */
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* Print an error message, and then exit. We typically use this
   function if there is no extra information in the error, and an
   analogous combination of fprintf and exit directly, otherwise. */
noreturn void fatal(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

/* To reduce the need for error checking code elsewhere in the
   program, this wrapper around malloc() will print an error message
   and then exit the program if an allocation fails. */
void *xmalloc(size_t size) {
    void *p = malloc(size);
    if (!p) {
        fprintf(stderr, "Out of memory in allocation of %zd bytes\n", size);
        exit(1);
    }
    return p;
}

/* xstrndup wraps strndup similarly to xmalloc with malloc. */
char *xstrndup(const char *s, size_t size) {
    char *p = strndup(s, size);
    if (!p) {
        fprintf(stderr, "Out of memory in allocation of up to %zd bytes\n",
		size);
        exit(1);
    }
    return p;
}

/* These functions with names ending in _c are analogous to the
   similarly-named functions from ctype.h, except that they are
   designed to work on plain "char" values, rather than "unsigned char
   or EOF". */
/* Decimal digit */
int isdigit_c(char c) {
    return c >= '0' && c <= '9';
}

/* Upper or lower-case letter. */
int isalpha_c(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* As in C, the first character of an identifier is either a letter or
   an underscore. */
int isident_first_c(char c) {
    return isalpha_c(c) || c == '_';
}

/* After the first character, indentifiers can also contain digits. */
int isident_rest_c(char c) {
    return isalpha_c(c) || c == '_' || isdigit_c(c);
}

/* Section: variables */

/* Variables in BCBASIC have a simple dynamic type system. They start
   out as uninitialized, and it is an error to read from an
   uninitialized variable before it has been written to. The first
   operation that writes to a variable established it as either an
   integer or an array, and the subsequent operations have to
   match. */
enum var_type {
    UNINIT,
    INT,
    ARRAY
};

/* This structure contains all the information about one
   variable. Variables are stored in a singly-linked list by the
   "next" field, and each variable records its name, but these are
   only used during translation and for error messages. In execution,
   statements link directly to the relevant variables. If the type is
   INT, then the int_val field is relevant; if the type is ARRAY, then
   array_val, length, and allocated are relevant. */
struct var {
    const char *name;
    struct var *next;
    enum var_type type;
    union {
	int64_t int_val;
	int64_t *array_val;
    };
    int64_t length;
    size_t allocated;
};

/* As we parse the program, we maintain all the variables in an
   unordered singly-linked list with "vars_head" as the starting
   point. */
struct var *vars_head = 0;

/* Look up a variable based on its name. Note that the name pointer p
   may not be null-terminated; instead the separate length argument
   determines where it ends. We do it this way to reduce the number of
   times the name has to be copied, since it isn't null-terminated in
   the program text. Returns NULL if no variable with that name
   exists. */
struct var *lookup_var(const char *p, size_t len) {
    struct var *vp;
    for (vp = vars_head; vp; vp = vp->next) {
	if (strlen(vp->name) == len && memcmp(p, vp->name, len) == 0)
	    return vp;
    }
    return 0;
}

/* Return the variable for a name, creating it as an uninitialized
   variable if it does not already exist. */
struct var *intern_var(const char *p, size_t len) {
    struct var *vp = lookup_var(p, len);
    if (vp)
	return vp;
    vp = xmalloc(sizeof(struct var));
    vp->name = xstrndup(p, len);
    vp->type = UNINIT;
    vp->next = vars_head;
    vars_head = vp;
    return vp;
}

/* Section: parsing */

/* BCBASIC doesn't have a complex expression syntax: there's only one
   operation per code line. Because of this, most places where an
   integer value would go there can only be a constant integer or the
   name of a variable. The argument to print functions is slightly
   more flexible in that it can also be a string
   constant. Collectively we call these "simple expressions", or
   "simple" for short. Because the varying parts of statements are
   mostly simple expressions, they are also used as the return values
   for parsing functions. */
enum simple_type {
    INT_CONST,
    STR_CONST,
    VAR
};

/* A simple expression is represented by either a 64-bit integer
constant, a character pointer for a string constant, or a pointer to a
variable. The choice between these is based on the "type" field. */
struct simple {
    enum simple_type type;
    union {
	int64_t int_const;
	const char *str_const;
	struct var *var_ref;
    };
};

/* Parser for an integer constant, which can only be a positive or
   negative decimal. Input P points to a point in the source code. If
   it contains an integer constant, RES is updated to hold the
   constant, and an advanced souce code pointer is returned. If the P
   does not point to a valid integer constant, returns 0. */
const char *scan_int(const char *p, struct simple *res) {
    long parsed;
    char *end;
    if (*p != '-' && !isdigit_c(*p))
	return 0;
    parsed = strtol(p, &end, 10);
    if (p == end) {
	return 0;
    }
    res->type = INT_CONST;
    res->int_const = (int64_t)parsed;
    return end;
}

/* Parser for a variable. This follows an analogous calling convention
   as scan_int. */
const char *scan_var(const char *p, struct simple *res) {
    const char *start = p;
    if (!isident_first_c(*p))
	return 0;
    p++;
    while (isident_rest_c(*p))
	p++;
    res->type = VAR;
    res->var_ref = intern_var(start, p - start);
    return p;
}

/*
  This function matches one line of the source code against a syntax
  pattern somewhat like the C standard library function "scanf". LINE
  should be a null-terminated string, not including the
  newline. FORMAT is the format string. RES and ERR_POS are output
  parameters. If the line matches the format, then data corresponding
  to the format specifiers and digits are written into up to 4
  positions in RES, and the number of entries written is returned. If
  the line does not match, the return value is 0, and ERR_POS is
  updated to the furthest point the parsing reached before failing.

  The following syntaxes are special in the format:

  %d = integer
  %v = variable identifier
  %e = simple (integer) expression, i.e. either %d or %v
  %s = string constant
  " " = 1 or more whitespace characters (space, tab)
  _ = 0 or more whitespace characters
  0-9 = write a constant integer (to distinguish cases)

  Whitespace before the format should already have been skipped, while
  every line implicitly ends with optional whitespace.
*/
int scan_line(const char *line, const char *format, struct simple *res,
	      int *err_pos) {
    const char *p = line;
    const char *f;
    int j = 0;
    for (f = format; *f; f++) {
	if (*f == '_') {
	    while (*p == ' ' || *p == '\t')
		p++;
	} else if (*f == ' ') {
	    if (*p != ' ' && *p != '\t')
		goto fail;
	    while (*p == ' ' || *p == '\t')
		p++;	    
	} else if (*f >= '0' && *f <= '9') {
	    int num = *f - '0';
	    res[j].type = INT_CONST;
	    res[j++].int_const = num;
	} else if (*f == '%') {
	    f++;
	    if (*f == 'd') {
		p = scan_int(p, &res[j]);
		if (p) j++; else goto fail;
	    } else if (*f == 'v') {
		p = scan_var(p, &res[j]);
		if (p) j++; else goto fail;
	    } else if (*f == 'e') {
		if (*p == '-' || isdigit_c(*p)) {
		    p = scan_int(p, &res[j]);
		} else if (isident_first_c(*p)) {
		    p = scan_var(p, &res[j]);
		} else {
		    goto fail;
		}
		if (p) j++; else goto fail;
	    } else if (*f == 's') {
                /* String constants may contain arbitrary characters
                   other than double quote or newline, but there is no
                   escape syntax. */
                const char *start;
		if (*p != '"')
		    goto fail;
		p++;
		start = p;
		while (*p != '"') {
		    if (*p == '\n' || !*p)
			goto fail;
		    p++;
		}
		assert(*p == '"');
		res[j].type = STR_CONST;
		res[j++].str_const = xstrndup(start, p - start);
		p++;
	    } else {
		assert(0);
	    }
	} else {
	    if (*p == *f) {
		p++;
	    } else {
		goto fail;
	    }
	}
    }
    while (*p == ' ' || *p == '\t')
	p++;
    if (*p != '\0') {
    fail:;
	int pos = p - line;
	if (p && pos > *err_pos)
	    *err_pos = pos;
	return 0;
    }
    assert(j <= 4);
    return j;
}

/* Each line of a BCBASIC program is one of 10 statement types: */
enum stmt_type {
    LET,
    PRINT,
    PRINTLN,
    BINOP,
    ALOAD,
    ASTORE,
    CLEAR,
    LENGTH,
    IFGOTO,
    GOTO
};

/* BCBASIC supports 6 arithmetic operators on integers: */
enum binop_type {
    PLUS,
    MINUS,
    TIMES,
    DIVIDE,
    MOD,
    POW
};

/* BCBASIC supports all 6 standard ways of comparing two integers: */
enum compare_type {
    LT,
    GT,
    LE,
    GE,
    EQ,
    NE
};

/* The stmt struct contains all the information about a single line of
   code (statement): it is both the translation-time and the runtime
   representation. Every statement is one 10 basic types (type), has a
   line number (line_num), and is part of a linked list (next). The
   remaining fields are relevant or not based on the type. b_type and
   c_type represent a more specific operation type for arithmetic and
   comparison operations. If the statement is assigning to a variable,
   this variable is lhs (from "left-hand side" of the assignment). For
   statements related to arrays, array_var is the array variable. For
   statements that take one or two simple expressions (recall these
   are variables or constants), they are arg1 and arg2. Goto
   statements have a target different from the next instruction:
   targ_line is the target's line number and targ_stmt is a pointer to
   the statement. */
struct stmt {
    uint64_t line_num;
    struct stmt *next;
    enum stmt_type type;
    union {
	enum binop_type b_type;
	enum compare_type c_type;
    };
    struct var *lhs;
    struct var *array_var;
    struct simple arg1;
    struct simple arg2;
    uint64_t targ_line;
    struct stmt *targ_stmt;
};

/* Statements are kept in a singly-linked list sorted by line number:
   we use these links for normal control flow (other than goto), and
   to look up statements by their line number.  Note that though it is
   a good practice, it is not required that the statements appear in
   order in the file. */

/* This pointer is the root of the linked list of statements. */
struct stmt *first_stmt = 0;

/* Because the most common place to insert new statements into the
   linked list is at the end, we permamently keep a pointer to a
   position near the end of the list to accelerate insertions near the
   end. Specifically we keep a pointer to the next pointer of the last
   statement that came before the statement we most recently
   inserted. */
struct stmt **last_prev_stmt = 0;

/* Insert a new statement into the sorted list of statements. Recall
   that the way insertion into a singly-linked list works, we need to
   keep track of a previous next pointer as well as a current node,
   because we need to change the previous next pointer when we insert
   a new node, and there are no backwards pointers in the list. */
void insert_stmt(struct stmt *new_sp) {
    struct stmt **prev;
    struct stmt *sp;
    if (last_prev_stmt && (*last_prev_stmt)->line_num < new_sp->line_num) {
        /* If the new statement would go after last_prev_stmt, start
           from there */
	prev = last_prev_stmt;
	sp = *prev;
    } else {
        /* Otherwise, start from the beginning. We treat the global
           variable first_stmt as a fake first next pointer. */
	prev = &first_stmt;
	sp = first_stmt;
    }
    for (; sp; prev = &sp->next, sp = sp->next) {
	if (sp->line_num > new_sp->line_num) {
	    /* sp is now pointing at the first statement with a higher
	       line numer, so we want to insert in front of sp. */
	    *prev = new_sp;
	    new_sp->next = sp;
	    last_prev_stmt = prev;
	    return;
	} else if (sp->line_num < new_sp->line_num) {
	    /* Still too low, keep going */
	} else {
	    fprintf(stderr, "Multiple statements with line number %lu\n",
		    (unsigned long)sp->line_num);
	    exit(1);
	}
    }
    /* No statements with higher numbers, so insert at the end */
    *prev = new_sp;
    new_sp->next = 0;
    last_prev_stmt = prev;
}

/* Search for a statement with the given line number, and return it or
   NULL if there is no statement with that line number. */
struct stmt *lookup_stmt(uint64_t line) {
    struct stmt *sp;
    for (sp = first_stmt; sp; sp = sp->next) {
	if (sp->line_num == line) {
	    return sp;
	} else if (sp->line_num > line) {
	    return 0;
	}
    }
    return 0;
}

/* If lines don't have an explicit line number, we assign line numbers
   sequentually: this global variable repesents the next one in
   sequence. */
uint64_t next_line_num = 1;

/* Parse one line of the input file into a statement, and return it;
   or return NULL for a comment line. Syntax errors are fatal. */
struct stmt *parse_line(const char *p) {
    uint64_t line_num;
    struct stmt *sp;
    struct simple res[4];
    while (*p == ' ' || *p == '\t')
	p++;
    if (*p == '#' ||
	(p[0] == 'r' && p[1] == 'e' && p[2] == 'm' && !isalpha_c(p[3]))) {
        /* A line starting with # or rem is a comment */
	return 0;
    }
    if (isdigit_c(*p)) {
        /* Try to parse an explicit line number */
	long parsed;
	char *num_end;
	parsed = strtol(p, &num_end, 10);
	if (p == num_end) {
	    return 0;
	}
	assert(parsed >= 0);
	line_num = (uint64_t)parsed;
	p = num_end;
	while (*p == ' ' || *p == '\t')
	    p++;
    } else {
	line_num = next_line_num;
    }
    sp = xmalloc(sizeof(struct stmt));
    sp->line_num = line_num;
    /* err_pos ("error position") represents the location of a syntax
       error in the line, by recording the longest distance into the
       line we got before matching one of the statement patterns
       failed. */
    int err_pos = 0;
    /* To parse a statement, we attempt to match it against patterns
       for all the possible statement types with calls to
       scan_line. If one succeeds we use the scanned results to fill
       in the fields of the statement. The only relevant side-effect
       of a failed call to scan_line is possibly updating err_pos. To
       reduce code duplication, similar patterns are distinguised with
       digits in them. */
    if (scan_line(p, "%v_=_%e", res, &err_pos)) {
	sp->type = LET;
	sp->lhs = res[0].var_ref;
	sp->arg1 = res[1];
    } else if (scan_line(p, "print0 %s", res, &err_pos) ||
	       scan_line(p, "print0 %e", res, &err_pos) ||
	       scan_line(p, "println1 %s", res, &err_pos) ||
	       scan_line(p, "println1 %e", res, &err_pos)) {
	if (res[0].int_const == 0) {
	    sp->type = PRINT;
	} else if (res[0].int_const == 1) {
	    sp->type = PRINTLN;
	} else {
	    assert(0);
	}
	sp->arg1 = res[1];
    } else if (scan_line(p, "%v_=_%e_+0_%e", res, &err_pos) ||
	       scan_line(p, "%v_=_%e_-1_%e", res, &err_pos) ||
	       scan_line(p, "%v_=_%e_*2_%e", res, &err_pos) ||
	       scan_line(p, "%v_=_%e_/3_%e", res, &err_pos) ||
	       scan_line(p, "%v_=_%e_ mod4 %e", res, &err_pos) ||
	       scan_line(p, "%v_=_%e_**5_%e", res, &err_pos)) {
	enum binop_type types[6] = {PLUS, MINUS, TIMES, DIVIDE, MOD, POW};
	sp->type = BINOP;
	sp->lhs = res[0].var_ref;
	sp->arg1 = res[1];
	sp->b_type = types[res[2].int_const];
	sp->arg2 = res[3];
    } else if (scan_line(p, "%v_=_%v_[_%e_]", res, &err_pos)) {
	sp->type = ALOAD;
	sp->lhs = res[0].var_ref;
	sp->array_var = res[1].var_ref;
	sp->arg1 = res[2];
    } else if (scan_line(p, "%v_[_%e_]_=_%e", res, &err_pos)) {
	sp->type = ASTORE;
	sp->array_var = res[0].var_ref;
	sp->arg1 = res[1];
	sp->arg2 = res[2];
    } else if (scan_line(p, "clear %v", res, &err_pos)) {
	sp->type = CLEAR;
	sp->array_var = res[0].var_ref;
    } else if (scan_line(p, "%v_=_length %v", res, &err_pos)) {
	sp->type = LENGTH;
	sp->lhs = res[0].var_ref;
	sp->array_var = res[1].var_ref;
    } else if (scan_line(p, "goto %d", res, &err_pos)) {
	sp->type = GOTO;
	sp->targ_line = res[0].int_const;
    } else if (scan_line(p, "if %e_<0_%e then goto %d", res, &err_pos) ||
	       scan_line(p, "if %e_<=1_%e then goto %d", res, &err_pos) ||
	       scan_line(p, "if %e_>2_%e then goto %d", res, &err_pos) ||
	       scan_line(p, "if %e_>=3_%e then goto %d", res, &err_pos) ||
	       scan_line(p, "if %e_==4_%e then goto %d", res, &err_pos) ||
	       scan_line(p, "if %e_<>5_%e then goto %d", res, &err_pos)) {
	enum compare_type types[6] = {LT, LE, GT, GE, EQ, NE};
	sp->type = IFGOTO;
	sp->arg1 = res[0];
	sp->c_type = types[res[1].int_const];
	sp->arg2 = res[2];
	sp->targ_line = res[3].int_const;
    } else {
        /* Print the err_pos with a caret, then die. */
	int i;
	fprintf(stderr, "Syntax error in line %lu:\n", line_num);
	fprintf(stderr, "%s\n", p);
	for (i = 0; i < err_pos; i++)
	    fprintf(stderr, " ");
	fprintf(stderr, "^\n");
	exit(1);
    }
    insert_stmt(sp);
    next_line_num = line_num + 1;
    return sp;
}

/* Read all of the contents of the file named FNAME into a newly
   allocated character buffer, and put a pointer to the buffer at the
   location pointed to by CONTENTS_P. Returns the number of characters
   in the file. A newline is added to the end of the file if the file
   does not already end in a newline, and there is also a null
   character after the file contents.
*/
size_t slurp_file(const char *fname, char **contents_p) {
    long res;
    struct stat stat_buf;
    size_t size;
    FILE *fh;
    char *buf;
    res = stat(fname, &stat_buf);
    if (res != 0) {
        fprintf(stderr, "Failed to access file %s: %s\n", fname,
                strerror(errno));
        exit(1);
    }
    size = stat_buf.st_size;
    buf = malloc(size + 2);
    if (!buf) {
        fprintf(stderr, "Failed to allocate memory for %s\n", fname);
        exit(1);
    }
    fh = fopen(fname, "r");
    if (!fh) {
        fprintf(stderr, "Failed to open %s for reading: %s\n", fname,
                strerror(errno));
        exit(1);
    }
    res = fread(buf, 1, size, fh);
    if (res != size) {
        fprintf(stderr, "Read only %ld bytes from %s\n", res, fname);
        exit(1);
    }
    res = fclose(fh);
    if (res) {
        fprintf(stderr, "Failure while closing %s: %s\n",
                fname, strerror(errno));
        exit(1);
    }
    if (buf[size - 1] != '\n') {
        buf[size++] = '\n';
    }
    buf[size] = '\0';
    *contents_p = buf;
    return size;
}

/* To read an entire program out of a file, we load the full contents
   of the file into a large buffer, and then parse each line after
   changing its ending newline into a null terminator. */
void parse_program(char *fname) {
    char *buf;
    char *line, *p;
    slurp_file(fname, &buf);
    line = buf;
    for (p = buf; *p; p++) {
	if (*p == '\n') {
	    *p = 0;
	    parse_line(line);
	    line = p + 1;
	}
    }
    free(buf);
}

/* Section: listing */

/* List back a simple expression, according to its type */
void list_simple(struct simple *ep) {
    if (ep->type == STR_CONST) {
	printf("\"%s\"", ep->str_const);
    } else if (ep->type == INT_CONST) {
	printf("%ld", (long)ep->int_const);
    } else if (ep->type == VAR) {
	printf("%s", ep->var_ref->name);
    } else {
	assert(0);
    }
}

/* List back a single statement into source form, according to its
   type. */
void list_stmt(struct stmt *sp) {
    const char *binop_names[] = {"+", "-", "*", "/", "mod", "**"};
    const char *compare_names[] = {"<", ">", "<=", ">=", "==", "<>"};
    switch (sp->type) {
    case LET:
	printf("%s = ", sp->lhs->name);
	list_simple(&sp->arg1);
	break;
    case PRINT:
    case PRINTLN:
	printf("print%s ", (sp->type == PRINTLN) ? "ln" : "");
	list_simple(&sp->arg1);
	break;
    case BINOP:
	printf("%s = ", sp->lhs->name);
	list_simple(&sp->arg1);
	printf(" %s ", binop_names[sp->b_type]);
	list_simple(&sp->arg2);
	break;
    case ALOAD:
	printf("%s = %s[", sp->lhs->name, sp->array_var->name);
	list_simple(&sp->arg1);
	printf("]");
	break;
    case ASTORE:
	printf("%s[", sp->array_var->name);
	list_simple(&sp->arg1);
	printf("] = ");
	list_simple(&sp->arg2);
	break;
    case CLEAR:
	printf("clear %s", sp->array_var->name);
	break;
    case LENGTH:
	printf("%s = length %s", sp->lhs->name, sp->array_var->name);
	break;
    case GOTO:
	printf("goto %lu", sp->targ_line);
	break;
    case IFGOTO:
	printf("if ");
	list_simple(&sp->arg1);
	printf(" %s ", compare_names[sp->c_type]);
	list_simple(&sp->arg2);
	printf(" then goto %lu", sp->targ_line);
	break;
    default:
	fprintf(stderr, "Unsupported stmt type %d in list\n", sp->type);
	exit(1);
    }
}


/* List back the entire program, with line numbers. This was a
   traditional feature of interactive BASIC interpreters, and it can
   also be useful for debugging problems with parsing. */
void list_program(void) {
    struct stmt *sp;
    for (sp = first_stmt; sp; sp = sp->next) {
	printf("%6lu ", sp->line_num);
	list_stmt(sp);
	printf("\n");
    }
}

/* After all the statements have been parsed, but before they can be
   executed, we go through and resolve each goto statement's line
   number into a pointer to its corresponding statement, so we don't
   have to do line number lookups repeatedly. */
void resolve_jumps(void) {
    struct stmt *sp;
    for (sp = first_stmt; sp; sp = sp->next) {
	if (sp->type == GOTO || sp->type == IFGOTO) {
	    struct stmt *targ_sp = lookup_stmt(sp->targ_line);
	    if (!targ_sp) {
		fprintf(stderr, "Missing taget line %lu "
			"for goto on line %lu\n", sp->targ_line, sp->line_num);
		exit(1);
	    }
	    sp->targ_stmt = targ_sp;
	}
    }
}

/* Section: arithmetic */

/* The BCBASIC "mod" operator is similar to C's "%", but it has
   different conventions related to signs and rounding: it corresponds
   to the remainder after integer division that rounds to negative
   infinity, and the sign of the result matches the sign of the second
   argument. */
int64_t do_modulo(int64_t arg1, int64_t arg2) {
    if (arg2 == 0)
	fatal("Modulo by zero");
    int64_t rem = arg1 % arg2;
    if (arg1 == 0)
	return 0;
    if (rem == 0)
	return 0;
    if (arg1 < 0 && arg2 > 0)
	return rem + arg2;
    if (arg1 > 0 && arg2 < 0)
	return rem - arg2;
    return rem;
}

/* Exponentiation ("**") is implemented for integers with a the
   classic square-and-multiply algorithm, and has explicit overflow
   checking. */
int64_t do_pow(int64_t arg1, int64_t arg2) {
    if (arg2 == 0)
	return 1;
    if (arg1 == 1)
	return 1;
    if (arg2 < 0)
	return 0;
    if ((arg1 ==   2 && arg2 >= 63) || (arg1 ==  3 && arg2 >  39) ||
	(arg1 ==   4 && arg2 >  31) || (arg1 ==  5 && arg2 >  27) ||
	(arg1 ==   6 && arg2 >  24) || (arg1 ==  7 && arg2 >  22) ||
	(arg1 ==   8 && arg2 >= 21) || (arg1 ==  9 && arg2 >  19) ||
	(arg1 >=  10 && arg2 >  18) || (arg1 >= 12 && arg2 >  17) ||
	(arg1 >=  14 && arg2 >  16) || (arg1 >= 16 && arg2 >  15) ||
	(arg1 >=  19 && arg2 >  14) || (arg1 >= 23 && arg2 >  13) ||
	(arg1 >=  29 && arg2 >  12) || (arg1 >  38 && arg2 >= 12) ||
	(arg1 >   52 && arg2 >= 11) || (arg1 >  78 && arg2 >= 10) ||
	(arg1 >= 128 && arg2 >=  9) || (arg1 > 234 && arg2 >=  8) ||
	(arg1 >= 512 && arg2 >=  7) || (arg1 > 1448 && arg2 >= 6) ||
	(arg1 > 6208 && arg2 >=  5) || (arg1 > 55108 && arg2 >= 4) ||
	(arg1 >= 2097152 && arg2 >= 3) ||
	(arg1 > 3037000499 && arg2 >= 2))
	return 0x7fffffffffffffff;
    int64_t prod = 1;
    int64_t base = arg1;
    int64_t exp = arg2;
    /* Idea: prod * base**exp is invariant */
    while (exp > 1) {
	if (exp & 1) {
	    prod = prod * base;
	    exp--;
	} else {
	    base = base * base;
	    exp = exp / 2;
	}
    }
    assert(exp == 1);
    return prod * base;
}

/* Most of BCBASIC's arithmetic operators are the same as C's
   operators on int64s. */
int64_t do_binop(enum binop_type b_type, int64_t arg1, int64_t arg2) {
    switch (b_type) {
    case PLUS: return arg1 + arg2;
    case MINUS: return arg1 - arg2;
    case TIMES: return arg1 * arg2;
    case DIVIDE: {
	if (arg2 == 0)
	    fatal("Divide by zero");
        if (arg1 == 0x8000000000000000 && arg2 == -1)
            fatal("Signed division overflow");
	return arg1 / arg2;
    }
    case MOD: return do_modulo(arg1, arg2);
    case POW: return do_pow(arg1, arg2);
    }
    assert(0);
}

/* BCBASIC's comparison operators have the same behavior as the
   corresponding C operators on int64s. */
int do_compare(enum compare_type c_type, int64_t arg1, int64_t arg2) {
    switch (c_type) {
    case LT: return arg1 < arg2;
    case LE: return arg1 <= arg2;
    case GT: return arg1 > arg2;
    case GE: return arg1 >= arg2;
    case EQ: return arg1 == arg2;
    case NE: return arg1 != arg2;
    }
    assert(0);
}

/* Section: arrays */

/* BCBASIC has arrays of 64-bit signed integers. Arrays do bounds
   checking and automatically grow as needed. Writing beyond the end
   of an array extends it, while reading beyond the end returns
   zero. Arrays keep track of their length, and negative offsets count
   backwards from the end. To avoid excessive copying when an array
   grows repeatedly, an array can have more space allocated than it
   currently requires, called "slack space": the slack space can
   handle small size increases, and then when the slack space is
   exhausted, the next size will be multiplicatively larger. Slack
   space corresponds to the difference between the "length" field and
   the "allocated" field. To implement the behavior of beyond-bounds
   accesses, the slack space and any other unused parts of the array
   are initialized to 0.
 */

/* Initialize an array, based on a given initial length. When it is
   first initialized an array has no slack, except that an empty array
   does have one entry allocated to avoid calling malloc with 0
   size. */
void array_init(struct var *avar, int64_t initial_len) {
    assert(initial_len >= 0);
    avar->type = ARRAY;
    avar->length = initial_len;
    avar->allocated = MAX(initial_len, 1);
    avar->array_val = xmalloc(sizeof(int64_t) * avar->allocated);
    memset(avar->array_val, 0, sizeof(int64_t) * avar->allocated);
}

/* Check whether an arbitrary memory location corresponds to an
   element of the given array. This can be useful for debugging. */
void check_array_loc(struct var *avar, void *ptr) {
    uint64_t x = (uint64_t)ptr;
    if ((x & 7) != 0) {
        printf("Pointer is not 8-byte aligned, array entries must be\n");
        return;
    }
    uint64_t offset = (uint64_t)ptr - (uint64_t)avar->array_val;
    int64_t index = offset >> 3;
    assert(index >= 0);
    if (index < avar->length) {
        printf("Location is in-bounds at index %ld\n", index);
    } else if (index < avar->allocated) {
        printf("Location is in slack space at index %ld\n", index);
    } else {
        printf("Location is out of bounds at index %ld\n", index);
    }
}

/* Load an element from an array. Handles out-of-bounds and negative
   indexes. */
int64_t array_load(struct var *avar, int64_t index) {
    if (avar->type == UNINIT) {
	fprintf(stderr, "Attempt to load from uninitialized array %s\n",
		avar->name);
	exit(1);
    }
    if (avar->type != ARRAY) {
	fprintf(stderr, "Attempt to load from non-array variable %s\n",
		avar->name);
	exit(1);
    }
    if ((index >= 0 && (size_t)index >= avar->allocated)
        || index < -avar->length)
	return 0;
    if (index < 0)
	index += avar->length;
    return avar->array_val[index];
}

/* Increase the size of an array to a larger length new_len, plus some
   slack space. Depending on how much slack the array used to have,
   the slack will be either 25% or 100%. */
void array_grow(struct var *avar, int64_t new_len) {
    if (new_len <= 0)
	fatal("Array size overflow");
    assert(new_len > avar->length);
    int64_t new_alloc;
    if (new_len <= 2 * avar->length) {
        new_alloc = new_len + (new_len / 4);
    } else {
        new_alloc = 2 * new_len;
    }
    if (new_alloc <= 0 || new_alloc >= (1L << 60))
	fatal("Array allocation overflow");
    assert(new_alloc > avar->length);
    avar->array_val = realloc(avar->array_val, sizeof(int64_t) * new_alloc);
    if (!avar->array_val) {
	fprintf(stderr, "Out of memory growing array to size %ld", new_len);
	exit(1);
    }
    memset(avar->array_val + avar->length, 0,
	   sizeof(int64_t) * (new_alloc - avar->length));
    avar->length = new_len;
    avar->allocated = new_alloc;
}

/* Store a value into an array, including handling negative indexes,
   growing, and slack space. */
void array_store(struct var *avar, int64_t index, int64_t val) {
    if (avar->type == UNINIT) {
        if (index < 0) {
            fatal("Negative index in initial store");
        } else if (index >= 0x7fffffffffffffff) {
            fatal("Index overflow in initial store");
        } else {
            array_init(avar, index + 1);
        }
    } else if (avar->type != ARRAY) {
	fprintf(stderr, "Attempt to store to non-array variable %s\n",
		avar->name);
	exit(1);
    }
    if (index < -avar->length) {
	fatal("Negative index out of bounds in store");
    } else if (index >= 0 && (size_t)index >= avar->allocated) {
        if (index >= 0x7fffffffffffffff)
            fatal("Index overflow in store");
	array_grow(avar, index + 1);
    } else if (index < 0) {
	index += avar->length;
    }
    assert(index >= 0);
    if (index >= avar->length) {
        /* We're extending the array, but into space that is already
           allocated. */
        assert(index < avar->allocated);
        avar->length = index + 1;
    }
    avar->array_val[index] = val;
}

/* Clearing an array frees the space used for its old contents (if
   any), and resets it to be empty. */
void array_clear(struct var *avar) {
    if (avar->type == UNINIT) {
	array_init(avar, 0);
    } else if (avar->type != ARRAY) {
	fprintf(stderr, "Attempt to clear non-array variable %s\n",
		avar->name);
	exit(1);
    } else {
	free(avar->array_val);
	array_init(avar, 0);
    }
}

/* Copy the contents of the RHS array (RHS = "right hand side" of the
   assignment) into the LHS array, replacing any previous contents of
   the LHS array. We include slack space in the LHS array based on the
   amount in the RHS array. */
void array_copy(struct var *lhs, struct var *rhs) {
    if (lhs->type == ARRAY)
	free(lhs->array_val);
    else
        lhs->type = ARRAY;
    if (rhs->type != ARRAY) {
	fatal("Array copy from uninitialized or non-array value");
    }
    lhs->length = rhs->length;
    int64_t new_alloc;
    if (rhs->allocated > rhs->length + (rhs->length / 4) + 1) {
        lhs->allocated = rhs->allocated * 2 - 1;
        double ratio = lhs->allocated / rhs->allocated;
        new_alloc = (size_t)(rhs->length * ratio);
    } else {
        lhs->allocated = rhs->length + (rhs->length / 4) + 1;
        new_alloc = rhs->length + (rhs->length / 4) + 1;
    }
    if (new_alloc <= 0 || new_alloc >= (1L << 60))
	fatal("Array copy overflow");
    lhs->array_val = xmalloc(sizeof(int64_t) * new_alloc);
    memcpy(lhs->array_val, rhs->array_val, sizeof(int64_t) * rhs->length);
    memset(lhs->array_val + lhs->length, 0,
	   sizeof(int64_t) * (new_alloc - lhs->length));
}

/* Print the contents of an array, separated by spaces. The "print"
   statement doesn't do this, it's only for debugging. */
void array_print(struct var *avar) {
    int64_t i;
    printf("[");
    for (i = 0; i < avar->length; i++) {
	if (i > 0)
	    printf(" ");
	printf("%ld", avar->array_val[i]);
    }
    printf("]");
    if (avar->allocated > avar->length)
        printf("+%ld", avar->allocated - avar->length);
}

/* Section: execution */

/* Evaluate a simple integer expression by returning either its
   constant value or the contents of its variable. */
int64_t eval_int_simple(struct simple *ep) {
    if (ep->type == INT_CONST) {
	return ep->int_const;
    } else if (ep->type == VAR) {
        if (ep->var_ref->type == UNINIT) {
            fprintf(stderr, "Use of uninitialized variable %s\n",
                    ep->var_ref->name);
            exit(1);
        }
	return ep->var_ref->int_val;
    } else {
	assert(0);
    }
}

/* Assign a new integer value to a variable. */
void assign_int(struct var *lhs, int64_t value) {
    if (lhs->type == ARRAY) {
	fprintf(stderr, "Can't assign integer value to array %s\n", lhs->name);
	exit(1);
    }
    lhs->type = INT;
    lhs->int_val = value;
}

/* Executing tracing is a debugging feature that needs to be enabled
   at compile time by defining the TRACE_EXEC macro. When enabled,
   BCBASIC will list each line of code as it is executed, and print
   notes about the contents of variables. */
#undef TRACE_EXEC

/* TRACE_PRINTF is like printf when execution tracing is enabled, and
   does nothing otherwise. */
/* TRACE(x) does x when execution tracing is enabled, and otherwise
   does nothing. */

#ifdef TRACE_EXEC
#define TRACE_PRINTF(...) printf(__VA_ARGS__)
#define TRACE(x) x
#else
#define TRACE_PRINTF(...) do {} while (0)
#define TRACE(x) do {} while (0)
#endif

/* Each type of statement is implemented by a method that takes a
   pointer to the statement structure, and returns a pointer to the
   next statement to execute. Non-control-flow statements just pass
   control to the next statement by returning sp->next. */
typedef struct stmt * (*opcode)(struct stmt *);

/* LET covers variable-to-variable assignment for both integers and
   arrays. It has this name because early versions of BASIC used a
   keyword "LET" to introduce assignment (like "LET x = y" instead of
   just "x = y"). */
struct stmt *exec_let(struct stmt *sp) {
    if (sp->lhs->type != INT && sp->arg1.type == VAR &&
        sp->arg1.var_ref->type != INT) {
	array_copy(sp->lhs, sp->arg1.var_ref);
	TRACE_PRINTF(": ");
	TRACE(array_print(sp->lhs));
    } else {
	int64_t val = eval_int_simple(&sp->arg1);
	assign_int(sp->lhs, val);
	TRACE_PRINTF(": %ld", val);
    }
    return sp->next;
}

/* PRINT can print either a constant string, or an integer. */
struct stmt *exec_print(struct stmt *sp) {
    TRACE_PRINTF(": ");
    if (sp->arg1.type == STR_CONST) {
	printf("%s", sp->arg1.str_const);
    } else {
	printf("%ld", eval_int_simple(&sp->arg1));
    }
    return sp->next;
}

/* PRINTLN is the same as PRINT, except that it also prints a trailing
   newline. */
struct stmt *exec_println(struct stmt *sp) {
    exec_print(sp);
    printf("\n");
    return sp->next;
}

/* Execute a binary arithmetic operator. */
struct stmt *exec_binop(struct stmt *sp) {
    int64_t arg1 = eval_int_simple(&sp->arg1);
    int64_t arg2 = eval_int_simple(&sp->arg2);
    int64_t result = do_binop(sp->b_type, arg1, arg2);
    assign_int(sp->lhs, result);
    TRACE_PRINTF(": %ld", result);
    return sp->next;
}

/* Load from an array and store into the LHS variable */
struct stmt *exec_aload(struct stmt *sp) {
    int64_t index = eval_int_simple(&sp->arg1);
    int64_t result = array_load(sp->array_var, index);
    assign_int(sp->lhs, result);
    TRACE_PRINTF(": ");
    TRACE(array_print(sp->array_var));
    TRACE_PRINTF("[%ld] = %ld", index, result);
    return sp->next;
}

/* Store into an array */
struct stmt *exec_astore(struct stmt *sp) {
    int64_t index = eval_int_simple(&sp->arg1);
    int64_t value = eval_int_simple(&sp->arg2);
    array_store(sp->array_var, index, value);
    TRACE_PRINTF(": [%ld] <- %ld", index, value);
    return sp->next;
}

/* Clear an array */
struct stmt *exec_clear(struct stmt *sp) {
    array_clear(sp->array_var);
    return sp->next;
}

/* Assign the length of an array to another variable. */
struct stmt *exec_length(struct stmt *sp) {
    if (sp->array_var->type != ARRAY) {
	fprintf(stderr, "Request for length of non-array variable %s\n",
		sp->array_var->name);
	exit(1);
    }
    assign_int(sp->lhs, sp->array_var->length);
    TRACE_PRINTF(": %ld", sp->array_var->length);
    return sp->next;
}

/* A GOTO statement just returns its target statement as the next
   statement to execute. */
struct stmt *exec_goto(struct stmt *sp) {
    return sp->targ_stmt;
}

/* IFGOTO is a branching statement that goes to either its target or
   the next statement based on an integer comparison. */
struct stmt *exec_ifgoto(struct stmt *sp) {
    int64_t arg1 = eval_int_simple(&sp->arg1);
    int64_t arg2 = eval_int_simple(&sp->arg2);
    TRACE_PRINTF(": %ld vs. %ld", arg1, arg2);
    if (do_compare(sp->c_type, arg1, arg2)) {
	return sp->targ_stmt;
    } else {
	return sp->next;
    }
}

/* This function is used to fill in unused locations in the opcode
   table, but should never be called. */
struct stmt *exec_missing(struct stmt *sp) {
    fatal("Unimplemented opcode");
}

/* The table of statement opcodes is sized as a power of two, so that
   code can do bounds checking with a bitmask. */
opcode opcodes[16] = {
    exec_let,        /* LET */
    exec_print,      /* PRINT */
    exec_println,    /* PRINTLN */
    exec_binop,      /* BINOP */
    exec_aload,      /* ALOAD */
    exec_astore,     /* ASTORE */
    exec_clear,      /* CLEAR */
    exec_length,     /* LENGTH */
    exec_ifgoto,     /* IFGOTO */
    exec_goto,       /* GOTO */
    exec_missing,    /* unused */
    exec_missing,    /* unused */
    exec_missing,    /* unused */
    exec_missing,    /* unused */
    exec_missing,    /* unused */
    exec_missing};   /* unused */


/* The main execution loop of BCBASIC calls the opcode for statements
   one at a time, the going to the next statement as appropriate. You
   can think of the variable "sp" in this code as being like the
   program counter. */
void exec_program(void) {
    struct stmt *sp = first_stmt;
    while (sp) {
	TRACE_PRINTF("%6lu ", sp->line_num);
	TRACE(list_stmt(sp));
	opcode fptr = opcodes[sp->type & 15];
	sp = (*fptr)(sp);
	TRACE_PRINTF("\n");
    }
}

/* Normally this function is never called. The only way it could get
   executed is via some sort of control-flow hijacking attack. */
void shellcode_target(void) {
    printf("\nIf this code is executed, it means that some sort of "
           "attack has happened!\n");
    exit(1);
}

/* BCBASIC requires exactly one command-line argument: the name of a
   BCBASIC source code file which it will parse, list, and then
   execute. */
int main(int argc, char **argv) {
    if (argc != 2) {
	fatal("Usage: bcbasic <filename>\n");
	exit(1);
    }
    char *fname = argv[1];
    parse_program(fname);
    list_program();
    resolve_jumps();
    exec_program();
    return 0;
}