/*
 * Copyright (c) 1998 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      H�gskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "make_cmds.h"

RCSID("$Id$");

#include <roken.h>
#include "parse.h"

int numerror;
extern FILE *yyin;
FILE *c_file;

extern void yyparse(void);

#ifdef YYDEBUG
extern int yydebug = 1;
#endif

char *filename;
char *table_name;

static struct command_list *commands;

void
add_command(char *function, 
	    char *help, 
	    struct string_list *aliases, 
	    unsigned flags)
{
    struct command_list *cl = malloc(sizeof(*cl));
    cl->function = function;
    cl->help = help;
    cl->aliases = aliases;
    cl->flags = flags;
    cl->next = NULL;
    if(commands) {
	*commands->tail = cl;
	commands->tail = &cl->next;
	return;
    }
    cl->tail = &cl->next;
    commands = cl;
}

static char *
quote(const char *str)
{
    char buf[1024]; /* XXX */
    const char *p;
    char *q;
    q = buf;
    
    *q++ = '\"';
    for(p = str; *p != '\0'; p++) {
	if(*p == '\n') {
	    *q++ = '\\';
	    *q++ = 'n';
	    continue;
	}
	if(*p == '\t') {
	    *q++ = '\\';
	    *q++ = 't';
	    continue;
	}
	if(*p == '\"' || *p == '\\')
	    *q++ = '\\';
	*q++ = *p;
    }
    *q++ = '\"';
    *q++ = '\0';
    return strdup(buf);
}

static void
generate_commands(void)
{
    char base[128];
    char cfn[128];
    const char *p;
    p = strrchr(table_name, '/');
    if(p == NULL)
	p = table_name;
    else
	p++;
    strcpy(base, p);
    p = strrchr(base, '.');
    if(p)
	*p == '\0';
    
    snprintf(cfn, sizeof(cfn), "%s.c", base);
    c_file = fopen(cfn, "w");
    
    fprintf(c_file, "/* Generated from %s */\n", filename);
    fprintf(c_file, "\n");
    fprintf(c_file, "#include <stddef.h>\n");
    fprintf(c_file, "#include <sl.h>\n");
    fprintf(c_file, "\n");

    {
	struct command_list *cl, *xl;
	char *p, *q;

	for(cl = commands; cl; cl = cl->next) {
	    for(xl = commands; xl != cl; xl = xl->next)
		if(strcmp(cl->function, xl->function) == 0)
		    break;
	    if(xl != cl)
		continue;
	    /* XXX hack for ss_quit */
	    if(strcmp(cl->function, "ss_quit") == 0) {
		fprintf(c_file, "int %s (int, char**);\n", cl->function);
		fprintf(c_file, "#define _ss_quit_wrap ss_quit\n\n", 
			cl->function, cl->function);
		continue;
	    }
	    fprintf(c_file, "void %s (int, char**);\n", cl->function);
	    fprintf(c_file, "static int _%s_wrap (int argc, char **argv)\n", 
		    cl->function);
	    fprintf(c_file, "{\n");
	    fprintf(c_file, "  %s (argc, argv);\n", cl->function);
	    fprintf(c_file, "  return 0;\n");
	    fprintf(c_file, "}\n\n");
	}

	fprintf(c_file, "SL_cmd %s[] = {\n", table_name);
	for(cl = commands; cl; cl = cl->next) {
	    struct string_list *sl;
	    sl = cl->aliases;
	    p = quote(sl->string);
	    q = quote(cl->help);
	    fprintf(c_file, "  { %s, _%s_wrap, %s },\n", p, cl->function, q);
	    free(p);
	    free(q);
    
	    for(sl = sl->next; sl; sl = sl->next) {
		p = quote(sl->string);
		fprintf(c_file, "  { %s },\n", p);
		free(p);
	    }
	}
	fprintf(c_file, "  { NULL },\n");
	fprintf(c_file, "};\n");
	fprintf(c_file, "\n");
    }
    fclose(c_file);
}

int
main(int argc, char **argv)
{
    char *p;
    set_progname(argv[0]);

    if(argc != 2) {
	fprintf(stderr, "Usage: %s command_table\n", __progname);
	exit(1);
    }
    filename = argv[1];
    yyin = fopen(filename, "r");
    if(yyin == NULL)
	err(1, "%s", filename);
    
    yyparse();
    
    generate_commands();

    if(numerror)
	return 1;
    return 0;
}
