/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include <apr_getopt.h>
#include "../common/error_debug.h"
#include "../common/expr-parser.h"
#include "../common/alloc.h"
#include "../core/nxlog.h"
#include "../core/core.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE

nxlog_t nxlog;


static nx_module_t *loadmodule(const char *modulename,
			       const char *type,
			       nx_ctx_t *ctx)
{
    nx_module_t *module;
    char dsoname[4096];

    module = apr_pcalloc(ctx->pool, sizeof(nx_module_t));
    module->dsoname = modulename;
    module->name = modulename;
    module->pool = ctx->pool;

    if ( nxlog.ctx->moduledir == NULL )
    {
	nxlog.ctx->moduledir = NX_MODULEDIR;
    }

    apr_snprintf(dsoname, sizeof(dsoname),
		 "%s"NX_DIR_SEPARATOR"%s"NX_DIR_SEPARATOR"%s"NX_MODULE_DSO_EXTENSION,
		 nxlog.ctx->moduledir, type, modulename);

    nx_module_load_dso(module, ctx, dsoname);
    nx_module_register_exports(ctx, module);

    return ( module );
}



int main(int argc, const char * const *argv, const char * const *env)
{
    apr_pool_t *pool;
    apr_file_t *input;
    char inputstr[10000];
    apr_size_t inputlen;
    nx_expr_statement_list_t *statements = NULL;
    nx_exception_t e;
    nx_module_t *module = NULL;
    apr_getopt_t *opt;
    int ch;
    const char *opt_arg;
    apr_status_t rv;

    static const apr_getopt_option_t options[] = {
	{ "moduledir", 'm', 1, "module direcotry" }, 
	{ NULL, 0, 1, NULL }, 
    };

    nx_init(&argc, &argv, &env);

    memset(&nxlog, 0, sizeof(nxlog_t));
    nxlog_set(&nxlog);
    nxlog.ctx = nx_ctx_new();
    nxlog.ctx->moduledir = NULL;
//    nxlog.ctx->loglevel = NX_LOGLEVEL_DEBUG;
    nxlog.ctx->loglevel = NX_LOGLEVEL_INFO;
    pool = nx_pool_create_child(NULL);

    apr_getopt_init(&opt, pool, argc, argv);
    while ( (rv = apr_getopt_long(opt, options, &ch, &opt_arg)) == APR_SUCCESS )
    {
	switch ( ch )
	{
	    case 'm':	/* configuration file */
		nxlog.ctx->moduledir = apr_pstrdup(pool, opt_arg);
		break;
	    default:
		log_error("invalid argument(s)");
		exit(-1);
	}
    }

    nx_ctx_register_builtins(nxlog.ctx);

    module = loadmodule("xm_syslog", "extension", nxlog.ctx);
    module = loadmodule("xm_charconv", "extension", nxlog.ctx);
    module = loadmodule("xm_exec", "extension", nxlog.ctx);

    CHECKERR_MSG(apr_file_open_stdin(&input, pool), "couldn't open stdin");

    memset(inputstr, 0, sizeof(inputstr));
    inputlen = sizeof(inputstr);
    CHECKERR(apr_file_read(input, inputstr, &inputlen));
    apr_file_close(input);

    try
    {
	statements = nx_expr_parse_statements(NULL, inputstr, pool, NULL, 1, 1);
    }
    catch(e)
    {
	log_exception(e);
	exit(1);
    }
    ASSERT(statements != NULL);

    apr_pool_destroy(pool);

    return ( 0 );
}
