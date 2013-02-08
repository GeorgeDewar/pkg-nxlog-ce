/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include <apr_portable.h>
#include <unistd.h>
#include <apr_file_info.h>
#include <apr_fnmatch.h>

#include "../../../common/module.h"
#include "../../../common/event.h"
#include "../../../common/error_debug.h"
#include "../../../common/config_cache.h"
#include "../../../common/expr-parser.h"
#include "../../../common/alloc.h"

#include "im_file.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

#define IM_FILE_DEFAULT_POLL_INTERVAL 1 /* The number of seconds to check the files for new data */
#define IM_FILE_MAX_READ 50 /* The max number of logs to read in a single iteration */
#define IM_FILE_CLOSE_THRESHOLD 10 /* The number of EOFs to close the file */
#define IM_FILE_MAX_OPEN_FILES 20 /* The max number of files which will be open at a time */


static void im_file_input_close(nx_module_t *module, nx_im_file_input_t *file) 
{
    nx_im_file_conf_t *imconf;

    ASSERT(file != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( file->input != NULL )
    {
	if ( file->input->desc.f != NULL )
	{
	    apr_file_close(file->input->desc.f);
	    file->input->desc.f = NULL;
	}
	apr_pool_destroy(file->input->pool);
	file->input = NULL;

	NX_DLIST_REMOVE(imconf->open_files, file, link);
	(imconf->num_open_files)--;
	ASSERT(imconf->num_open_files >= 0);

	log_debug("file %s closed", file->name);
    }
}



static void im_file_input_blacklist(nx_module_t *module, nx_im_file_input_t *file)
{
    im_file_input_close(module, file);

    if ( file->blacklist_interval == 0 )
    {
	file->blacklist_interval = 1;
    }
    else
    {
	file->blacklist_interval *= 2;
    }
    file->blacklist_until = apr_time_now() + file->blacklist_interval * APR_USEC_PER_SEC;
}



static void im_file_fill_buffer(nx_module_t *module, nx_im_file_input_t *file, boolean *got_eof)
{
    apr_status_t rv;
    apr_size_t len;
    nx_module_input_t *input;

    ASSERT(file != NULL);
    
    input = file->input;
    ASSERT(input != NULL);
    ASSERT(file->input->buf != NULL);
    ASSERT(file->input->module != NULL);
    ASSERT(file->input->desc_type == APR_POLL_FILE);
    ASSERT(file->input->desc.f != NULL);

    //log_info("bufstart: %d, buflen: %d", input->bufstart, input->buflen);

    if ( input->bufstart == input->bufsize )
    {
	input->bufstart = 0;
	input->buflen = 0;
    }
    if ( input->buflen == 0 )
    {
	input->bufstart = 0;
    }

    ASSERT(input->bufstart + input->buflen <= input->bufsize);

    len = (apr_size_t) (input->bufsize - (input->buflen + input->bufstart));

    rv = apr_file_read(input->desc.f, input->buf + input->bufstart + input->buflen, &len);

    if ( rv != APR_SUCCESS )
    {
	if ( rv == APR_EOF )
	{
	    log_debug("Module %s got EOF from %s", input->module->name, file->name);
	    *got_eof = TRUE;
	    file->blacklist_until = 0;
	    file->blacklist_interval = 0;
	}
	else if ( rv == APR_EAGAIN )
	{
	    nx_panic("im_file got EAGAIN for read in module %s", input->module->name);
	}
	else
	{
	    log_aprerror(rv, "Module %s couldn't read from file %s", input->module->name, file->name);
	    im_file_input_blacklist(module, file);
	    *got_eof = TRUE; // needed to skip to next file in im_file_read
	}
    }
    else
    {
	file->blacklist_until = 0;
	file->blacklist_interval = 0;
    }

    input->buflen += (int) len;
    ASSERT(input->buflen <= input->bufsize);
}



static void im_file_eval_filename(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    nx_expr_eval_ctx_t ctx;
    nx_value_t value;

    imconf = (nx_im_file_conf_t *) module->config;

    ASSERT(imconf->filename_expr != NULL);
    ASSERT(imconf->filename_expr->type != NX_EXPR_TYPE_VALUE);

    ctx.module = module;
    ctx.logdata = NULL;

    nx_expr_evaluate(&ctx, &value, imconf->filename_expr);
    if ( value.defined == FALSE )
    {
	throw_msg("%s File directive evaluated to undef", module->name);
    }

    if ( value.type != NX_VALUE_TYPE_STRING )
    {
	throw_msg("%s File directive evaluated to '%', string type required",
		  module->name, nx_value_type_to_string(value.type));
    }
    
    // update filename
    apr_cpystrn(imconf->filename, value.string->buf, sizeof(imconf->filename));
    nx_value_kill(&value);

    if ( strlen(imconf->filename) == 0 )
    {
	throw_msg("%s File directive evaluated to an empty string", module->name);
    }

    return;
}



static void im_file_input_get_filepos(nx_module_t *module, nx_im_file_input_t *file) 
{
    apr_off_t filepos;
    apr_status_t rv;

    ASSERT(file != NULL);
    ASSERT(file->input != NULL);
    ASSERT(file->input->desc.f != NULL);

    filepos = 0;
    if ( (rv = apr_file_seek(file->input->desc.f, APR_CUR, &filepos)) != APR_SUCCESS )
    {
	im_file_input_blacklist(module, file);
	log_aprerror(rv, "failed to get file position for %s", file->name);
    }
    else
    {
	file->filepos = filepos;
    }
}



/**
 * Return TRUE if a newly opened file was added
 */

static boolean im_file_input_open(nx_module_t *module,
				  nx_im_file_input_t **file,
				  apr_finfo_t *finfo,
				  boolean readfromlast,
				  boolean existed)
{
    nx_im_file_conf_t *imconf;
    apr_pool_t *pool;
    apr_finfo_t file_info;
    boolean opened = FALSE;
    nx_exception_t e;

    ASSERT(file != NULL);
    ASSERT(*file != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( ((*file)->blacklist_until != 0) && ((*file)->blacklist_until > apr_time_now()) )
    {
	log_debug("ignoring blacklisted file %s until blacklisting expires", (*file)->name);

	return ( FALSE );
    }

    try
    {
	if ( (*file)->input == NULL )
	{
	    log_debug("opening %s", (*file)->name);
	    pool = nx_pool_create_child((*file)->pool);
	    (*file)->input = nx_module_input_new(module, pool);
	    NX_DLIST_INSERT_TAIL(imconf->open_files, *file, link);
	    (imconf->num_open_files)++;
	
	    nx_module_input_data_set((*file)->input, "filename", apr_pstrdup(pool, (*file)->name));
	    CHECKERR_MSG(apr_file_open(&((*file)->input->desc.f), (*file)->name, APR_READ,
				       APR_OS_DEFAULT, pool), "failed to open %s", (*file)->name);
	    (*file)->input->desc_type = APR_POLL_FILE;
	    (*file)->input->inputfunc = imconf->inputfunc;

	    if ( finfo == NULL )
	    {
		CHECKERR_MSG(apr_file_info_get(&file_info, APR_FINFO_INODE | APR_FINFO_MTIME | APR_FINFO_SIZE,
					       (*file)->input->desc.f), 
			     "failed to query file information for %s", (*file)->name);
		(*file)->inode = file_info.inode;
		(*file)->mtime = file_info.mtime;
		(*file)->size = file_info.size;
	    }
	    else
	    {
		(*file)->inode = finfo->inode;
		(*file)->mtime = finfo->mtime;
		(*file)->size = finfo->size;
	    }

	    if ( (*file)->filepos > 0 )
	    {
		CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_SET, &((*file)->filepos)),
			     "failed to seek to file position %lu in file %s",
			     (*file)->filepos, (*file)->name);
	    }
	    else if ( readfromlast == TRUE )
	    {
		apr_off_t fileend = 0;
		
		CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_END, &fileend),
			     "failed to seek to end of input in file %s", (*file)->name);
		(*file)->filepos = fileend;
	    }
	    (*file)->blacklist_until = 0;
	    (*file)->blacklist_interval = 0;
	    opened = TRUE;
	}
	
	if ( ((*file)->filepos > 0) && (((*file)->filepos > (*file)->size) ||
				     ((finfo != NULL) && ((*file)->filepos > finfo->size))) )
	{ // truncated, seek back to start
	    log_info("input file %s was truncated, restarting from beginning", (*file)->name);
	    (*file)->filepos = 0;
	    
	    CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_SET, &((*file)->filepos)),
			 "failed to seek to beginning of file %s", (*file)->name);
	}
	
	(*file)->num_eof = 0;

	if ( opened == TRUE )
	{
	    if ( imconf->num_open_files > IM_FILE_MAX_OPEN_FILES )
	    {
		log_debug("maximum number (%d) of files open, closing current", imconf->num_open_files);
		im_file_input_close(module, *file);
	    }
	    else
	    {
		log_debug("file %s opened", (*file)->name);
	    }
	}
	else
	{
	    log_debug("file %s already opened", (*file)->name);
	}

	ASSERT((*file)->inode != 0);
	ASSERT((*file)->mtime != 0);
    }
    catch(e)
    {
	if ( APR_STATUS_IS_ENOENT(e.code) )
	{
	    if ( (existed == TRUE) || (imconf->filename_const == FALSE) )
	    {
		if ( existed == TRUE )
		{
		    log_warn("input file was deleted: %s", (*file)->name);
		}
		else
		{
		    log_warn("input file does not exist: %s", (*file)->name);
		}
		apr_hash_set(imconf->files, (*file)->name, APR_HASH_KEY_STRING, NULL);
		im_file_input_close(module, *file);
		apr_pool_destroy((*file)->pool);
		*file = NULL;
	    }
	    else
	    {
		log_warn("input file does not exist: %s", (*file)->name);
		im_file_input_blacklist(module, *file);
	    }
	}
	else
	{
	    log_exception(e);
	    im_file_input_blacklist(module, *file);
	}
    }

    return ( opened );
}



static boolean im_file_input_check_close(nx_module_t *module) 
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->num_open_files < IM_FILE_MAX_OPEN_FILES )
    {
	return ( FALSE );
    }
    for ( file = NX_DLIST_FIRST(imconf->open_files);
	  file != NULL;
	  file = NX_DLIST_NEXT(file, link) )
    {
	if ( file->num_eof > 0 )
	{
	    im_file_input_get_filepos(module, file);
	    im_file_input_close(module, file);
	    return ( TRUE );
	}
    }
    return ( FALSE );
}



static boolean im_file_has_unread_data(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    boolean retval = FALSE;
    apr_hash_index_t *idx;
    const char *fname;
    apr_ssize_t keylen;
    nx_im_file_input_t *file = NULL;
    apr_pool_t *pool;

    imconf = (nx_im_file_conf_t *) module->config;

    pool = nx_pool_create_child(module->pool);

    // TODO: keep the iterator so we don't restart from the beginning every time
    for ( idx = apr_hash_first(pool, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	ASSERT(file != NULL);
	ASSERT(fname != NULL);

	if ( file->new_size > file->filepos )
	{
	    log_debug("file '%s' has unread data (%u > %u)", fname,
		      (unsigned int) file->new_size, (unsigned int) file->filepos);
	    im_file_input_check_close(module);
	    if ( im_file_input_open(module, &file, NULL, FALSE, TRUE) == TRUE )
	    {
		retval = TRUE;
		break;
	    }
	}
    }
    apr_pool_destroy(pool);

    return ( retval );
}



static boolean im_file_check_files(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    apr_pool_t *pool;
    const char *fname;
    boolean volatile retval = FALSE;
    nx_exception_t e;
    apr_hash_index_t * volatile idx;
    apr_ssize_t keylen;
    nx_im_file_input_t *file;

    imconf = (nx_im_file_conf_t *) module->config;

    pool = nx_pool_create_child(module->pool);

    // check if it is already added to the list
    for ( idx = apr_hash_first(pool, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	ASSERT(file != NULL);
	ASSERT(fname != NULL);

	if ( (file->blacklist_until != 0) && (file->blacklist_until > apr_time_now()) )
	{
	    log_debug("not checking file %s until blacklisting expires", file->name);
	    continue;
	}

	try
	{
	    apr_finfo_t finfo;
	    boolean needopen = FALSE;

	    CHECKERR(apr_stat(&finfo, fname,
			      APR_FINFO_INODE | APR_FINFO_MTIME | APR_FINFO_SIZE, pool));

	    if ( file->inode == 0 )
	    { // no stat info stored yet (initial open failed)
		needopen = TRUE;
	    }
	    else
	    {
		if ( file->inode != finfo.inode )
		{
		    log_warn("inode changed for '%s': reopening possibly rotated file", fname);
		    im_file_input_close(module, file);
		    file->filepos = 0;
		    retval = TRUE;
		    needopen = TRUE;
		}
		
		ASSERT(file->mtime != 0);
		if ( file->mtime != finfo.mtime )
		{
		    log_debug("mtime of file '%s' changed", fname);
		    file->new_mtime = finfo.mtime;
		    retval = TRUE;
		    needopen = TRUE;
		}
		
		if ( file->size < finfo.size )
		{
		    log_debug("file size of '%s' increased since last read", fname);
		    file->new_size = finfo.size;
		    retval = TRUE;
		    needopen = TRUE;
		}
	    
		if ( (file->filepos > 0) && (finfo.size < file->filepos) )
		{
		    log_debug("file '%s' was truncated", fname);
		    file->new_size = finfo.size;
		    retval = TRUE;
		    needopen = TRUE;
		}

		if ( finfo.size > file->filepos )
		{
		    log_debug("file '%s' has unread data (%u > %u)", fname,
			      (unsigned int) finfo.size, (unsigned int) file->filepos);
		    file->new_size = finfo.size;
		    retval = TRUE;
		    needopen = TRUE;
		}
	    }
	    
	    if ( needopen == TRUE )
	    {
		im_file_input_check_close(module);
		im_file_input_open(module, &file, &finfo, FALSE, TRUE);
	    }
	}
	catch(e)
	{
	    if ( APR_STATUS_IS_ENOENT(e.code) )
	    {
		if ( file->blacklist_until != 0 )
		{
		    log_warn("input file does not exist: %s", fname);
		    im_file_input_blacklist(module, file);
		}
		else
		{
		    log_warn("input file was deleted: %s", fname);
		    apr_hash_set(imconf->files, fname, keylen, NULL);
		    im_file_input_close(module, file);
		    apr_pool_destroy(file->pool);
		}
	    }
	    else
	    {
		log_exception(e);
		im_file_input_blacklist(module, file);
	    }
	}
    }

    apr_pool_destroy(pool);

    return ( retval );
}



static boolean im_file_add_file(nx_module_t *module, const char *fname, boolean readfromlast)
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;
    apr_off_t filepos = 0;
    int64_t savedpos = 0;
    boolean volatile retval = FALSE;
    apr_pool_t *pool;
    boolean existed = FALSE;

    imconf = (nx_im_file_conf_t *) module->config;

    // check if it is already added to the list
    file = (nx_im_file_input_t *) apr_hash_get(imconf->files, fname, APR_HASH_KEY_STRING);

    if ( file == NULL )
    { // not found, add it
	log_debug("adding file: %s", fname);

	if ( imconf->savepos == TRUE )
	{
	    if ( nx_config_cache_get_int(module->name, fname, &savedpos) == TRUE )
	    {
		filepos = (apr_off_t) savedpos;
		if ( filepos > 0 )
		{
		    existed = TRUE;
		}
	    }
	    log_debug("module %s read saved position %ld for %s", module->name,
		      (long int) filepos, fname);
	}

	pool = nx_pool_create_child(module->pool);
	file = apr_pcalloc(pool, sizeof(nx_im_file_input_t));
	file->pool = pool;
	file->filepos = filepos;
	file->name = apr_pstrdup(pool, fname);

	im_file_input_check_close(module);
	retval = im_file_input_open(module, &file, NULL, readfromlast, existed);
	if ( file != NULL )
	{
	    apr_hash_set(imconf->files, file->name, APR_HASH_KEY_STRING, (void *) file);
	}
    }
    else
    {
	log_debug("file %s already added", file->name);
    }

    return ( retval );
}



/*
 * Read directory contents and add files matching the wildcard pattern
 * Return true when new files were added
 */
static boolean im_file_glob_dir(nx_module_t *module,
				apr_pool_t *pool,
				const char *dirname,
				const char *fname,
				boolean readfromlast)
{
    nx_exception_t e;
    apr_dir_t *dir;
    char tmp[APR_PATH_MAX];
    boolean volatile retval = FALSE;
    apr_status_t rv;

    log_debug("reading directory entries under '%s' to check for matching files", dirname);
    rv = apr_dir_open(&dir, dirname, pool);
    if ( rv != APR_SUCCESS )
    {
	log_aprerror(rv, "failed to open directory: %s", dirname);
	return ( FALSE );
    }

    try
    {
	apr_finfo_t finfo;
	nx_im_file_conf_t *imconf;

	imconf = (nx_im_file_conf_t *) module->config;

	while ( apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE, dir) == APR_SUCCESS )
	{
	    log_debug("checking '%s' against wildcard '%s':", finfo.name, fname);
	    if ( finfo.filetype == APR_REG )
	    {
#ifdef WIN32
		if ( apr_fnmatch(fname, finfo.name, APR_FNM_CASE_BLIND) == APR_SUCCESS )
#else
		if ( apr_fnmatch(fname, finfo.name, 0) == APR_SUCCESS )
#endif
		{
		    log_debug("'%s' matches wildcard '%s'", finfo.name, fname);
		    apr_snprintf(tmp, sizeof(tmp), "%s"NX_DIR_SEPARATOR"%s", dirname, finfo.name);
		    if ( im_file_add_file(module, tmp, readfromlast) == TRUE )
		    {
			retval = TRUE;
		    }
		}
		else
		{
		    log_debug("'%s' does not match wildcard '%s'", finfo.name, fname);
		}
	    }
	    else if ( finfo.filetype == APR_DIR )
	    { 
		apr_snprintf(tmp, sizeof(tmp), "%s"NX_DIR_SEPARATOR"%s", dirname, finfo.name);
		if ( imconf->recursive == TRUE )
		{
		    if ( !((strcmp(finfo.name, ".") == 0) || (strcmp(finfo.name, "..") == 0)) )
		    {
			log_debug("recursively checking directory contents under '%s'", finfo.name);
			if ( im_file_glob_dir(module, pool, tmp, fname, readfromlast) == TRUE )
			{
			    retval = TRUE;
			}
		    }
		    else
		    {
			log_debug("ignoring directory entry '%s'", finfo.name);
		    }
		}
		else
		{
		    log_debug("recursion not enabled, ignoring subdirectory %s", tmp);
		}
	    }
	    else
	    {
		log_debug("skipping unsupported type %s", finfo.name);
	    }
	}
    }
    catch(e)
    {
	apr_dir_close(dir);
	rethrow(e);
    }
    apr_dir_close(dir);

    return ( retval );
}



/** Check for files matching the wildcarded name
 *  Return true if a new file was found
 */
static boolean im_file_check_new(nx_module_t *module, boolean readfromlast)
{
    nx_im_file_conf_t *imconf;
    apr_pool_t *pool = NULL;
    nx_exception_t e;
    boolean volatile retval = FALSE;

    imconf = (nx_im_file_conf_t *) module->config;

    try
    {
	if ( imconf->filename_const == FALSE )
	{
	    im_file_eval_filename(module);
	}
	if ( apr_fnmatch_test(imconf->filename) != 0 )
	{
	    char *idx;
	    char *fname;
	    char *dirname;
	    
	    log_debug("Value specified for File parameter contains wildcards: '%s'", imconf->filename);
	
	    pool = nx_pool_create_child(module->pool);
	
	    idx = strrchr(imconf->filename, NX_DIR_SEPARATOR[0]);
	    if ( idx == NULL )
	    { // relative path with filename only
		fname = imconf->filename;
		log_debug("A relative path was specified in File, checking directory entries under spooldir");
		if ( im_file_glob_dir(module, pool, "."NX_DIR_SEPARATOR, fname, readfromlast) == TRUE )
		{
		    retval = TRUE;
		}
	    }
	    else
	    {
		dirname = apr_pstrndup(pool, imconf->filename, (apr_size_t) (idx - imconf->filename));
		fname = idx + 1;
		if ( im_file_glob_dir(module, pool, dirname, fname, readfromlast) == TRUE )
		{
		    retval = TRUE;
		}
	    }
	}
	else
	{
	    im_file_add_file(module, imconf->filename, imconf->readfromlast);
	}
    }
    catch(e)
    {
	if ( pool != NULL )
	{
	    apr_pool_destroy(pool);
	}
	rethrow(e);
    }
    if ( pool != NULL )
    {
	apr_pool_destroy(pool);
    }
    
    return ( retval );
}




static void im_file_add_event(nx_module_t *module, boolean delayed)
{
    nx_event_t *event;
    nx_im_file_conf_t *imconf;

    imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf->event == NULL);

    event = nx_event_new();
    event->module = module;
    if ( delayed == TRUE )
    {
	event->delayed = TRUE;
	event->time = apr_time_now() + (int) (APR_USEC_PER_SEC * imconf->poll_interval);
    }
    else
    {
	event->delayed = FALSE;
    }
    event->type = NX_EVENT_READ;
    event->priority = module->priority;
    nx_event_add(event);
    imconf->event = event;

}



static void im_file_read(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    nx_logdata_t *logdata;
    boolean got_eof;
    boolean got_data;
    int evcnt = 0;

    ASSERT(module != NULL);
    imconf = (nx_im_file_conf_t *) module->config;
    imconf->event = NULL;

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    if ( imconf->currsrc == NULL )
    {
	imconf->currsrc = NX_DLIST_FIRST(imconf->open_files);
	if ( (imconf->currsrc == NULL) && (apr_hash_count(imconf->files) == 0) )
	{
	    if ( imconf->warned_no_input_files == FALSE )
	    {
		log_warn("Module %s has no input files to read", module->name);
	    }
	    imconf->warned_no_input_files = TRUE;
	}
	else
	{
	    imconf->warned_no_input_files = FALSE;
	}
    }

    for ( evcnt = 0; evcnt < IM_FILE_MAX_READ; )
    {
	if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
	{
	    break;
	}

	if ( imconf->currsrc == NULL )
	{
	    break;
	}
	got_data = FALSE;
	got_eof = FALSE;
	if ( (imconf->currsrc->input != NULL) &&
	     (logdata = imconf->currsrc->input->inputfunc->func(
		 imconf->currsrc->input, imconf->currsrc->input->inputfunc->data)) != NULL )
	{
	    //log_info("read: [%s]", logdata->raw_event->buf);
	    nx_module_add_logdata_input(module, imconf->currsrc->input, logdata);
	    nx_config_cache_set_int(module->name, imconf->currsrc->name,
				    (int) imconf->currsrc->filepos);
	    got_data = TRUE;
	    evcnt++;
	}
	else
	{
	    im_file_fill_buffer(module, imconf->currsrc, &got_eof);
	    if ( (imconf->currsrc->input != NULL) &&
		 (logdata = imconf->currsrc->input->inputfunc->func(
		     imconf->currsrc->input, imconf->currsrc->input->inputfunc->data)) != NULL )
	    {
		nx_module_add_logdata_input(module, imconf->currsrc->input, logdata);
		nx_config_cache_set_int(module->name, imconf->currsrc->name,
					(int) imconf->currsrc->filepos);
		got_data = TRUE;
		evcnt++;
	    }
	}
	if ( got_eof == TRUE )
	{
	    //log_info("got EOF from %s", imconf->currsrc->name);

	    if ( got_data == FALSE )
	    {
		if ( imconf->currsrc->new_size > 0 )
		{
		    imconf->currsrc->size = imconf->currsrc->new_size;
		    imconf->currsrc->filepos = imconf->currsrc->new_size;
		}
		if ( imconf->currsrc->new_mtime > 0 )
		{
		    imconf->currsrc->mtime = imconf->currsrc->new_mtime;
		}

		(imconf->currsrc->num_eof)++;
		imconf->currsrc = NX_DLIST_NEXT(imconf->currsrc, link);
		continue;
	    }
	}
	else // got_eof == FALSE
	{
	    imconf->currsrc->num_eof = 0;
	}
    }

    if ( (evcnt < IM_FILE_MAX_READ) && (evcnt < IM_FILE_MAX_OPEN_FILES) )
    {
	if ( (im_file_has_unread_data(module) == TRUE) ||
	     (im_file_check_files(module) == TRUE) )
	{ // force undelayed event
	    evcnt++;
	}
	if ( (evcnt == 0) && (im_file_check_new(module, FALSE) == TRUE) )
	{ // force undelayed event
	    evcnt++;
	}
    }

    if ( nx_module_get_status(module) == NX_MODULE_STATUS_RUNNING )
    {
	if ( evcnt == 0 )
	{
	    im_file_add_event(module, TRUE);
	}
	else
	{
	    im_file_add_event(module, FALSE);
	}
    }
}



static void im_file_config(nx_module_t *module)
{
    const nx_directive_t * volatile curr;
    nx_im_file_conf_t * volatile imconf;
    nx_exception_t e;

    ASSERT(module->directives != NULL);
    curr = module->directives;

    imconf = apr_pcalloc(module->pool, sizeof(nx_im_file_conf_t));
    module->config = imconf;

    while ( curr != NULL )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( strcasecmp(curr->directive, "file") == 0 )
	{
	    if ( imconf->filename_expr != NULL )
	    {
		nx_conf_error(curr, "file is already defined");
	    }

	    try
	    {
		imconf->filename_expr = nx_expr_parse(module, curr->args, module->pool,
						      curr->filename, curr->line_num, curr->argsstart);
		if ( !((imconf->filename_expr->rettype == NX_VALUE_TYPE_STRING) ||
		       (imconf->filename_expr->rettype == NX_VALUE_TYPE_UNKNOWN)) )
		{
		    throw_msg("string type required in expression, found '%s'",
			      nx_value_type_to_string(imconf->filename_expr->rettype));
		}
		if ( imconf->filename_expr->type == NX_EXPR_TYPE_VALUE )
		{
		    ASSERT(imconf->filename_expr->value.defined == TRUE);
		    if ( imconf->filename_expr->value.type != NX_VALUE_TYPE_STRING )
		    {
			throw_msg("%s File directive evaluated to '%', string type required",
				  module->name, nx_value_type_to_string(imconf->filename_expr->value.type));
		    }
		    apr_cpystrn(imconf->filename, imconf->filename_expr->value.string->buf,
				sizeof(imconf->filename));
		    imconf->filename_const = TRUE;
		}
	    }
	    catch(e)
	    {
		log_exception(e);
		nx_conf_error(curr, "invalid expression in 'File', string type required");
	    }
	}
	else if ( strcasecmp(curr->directive, "savepos") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "recursive") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "ReadFromLast") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "InputType") == 0 )
	{
	    if ( imconf->inputfunc != NULL )
	    {
		nx_conf_error(curr, "InputType is already defined");
	    }

	    if ( curr->args != NULL )
	    {
		imconf->inputfunc = nx_module_input_func_lookup(curr->args);
	    }
	    if ( imconf->inputfunc == NULL )
	    {
		nx_conf_error(curr, "Invalid InputType '%s'", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "PollInterval") == 0 )
	{
	    if ( sscanf(curr->args, "%f", &(imconf->poll_interval)) != 1 )
	    {
		nx_conf_error(curr, "invalid PollInterval: %s", curr->args);
            }
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
	curr = curr->next;
    }

    if ( imconf->inputfunc == NULL )
    {
	imconf->inputfunc = nx_module_input_func_lookup("linebased");
    }
    ASSERT(imconf->inputfunc != NULL);

    imconf->savepos = TRUE;
    nx_cfg_get_boolean(module->directives, "savepos", &(imconf->savepos));

    imconf->readfromlast = TRUE;
    nx_cfg_get_boolean(module->directives, "ReadFromLast", &(imconf->readfromlast));

    imconf->recursive = TRUE;
    nx_cfg_get_boolean(module->directives, "recursive", &(imconf->recursive));

    if ( imconf->filename_expr == NULL )
    {
	nx_conf_error(module->directives, "'File' missing for module im_file");
    }

    if ( imconf->poll_interval == 0 )
    {
	imconf->poll_interval = IM_FILE_DEFAULT_POLL_INTERVAL;
    }

    imconf->open_files = apr_pcalloc(module->pool, sizeof(nx_im_file_input_list_t));
    imconf->files= apr_hash_make(module->pool);
}



static void im_file_start(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;
  
    im_file_check_new(module, imconf->readfromlast);
    im_file_add_event(module, FALSE);
}



static void im_file_stop(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;
    apr_hash_index_t *idx;
    apr_ssize_t keylen;
    apr_pool_t *pool;
    const char *fname;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    imconf = (nx_im_file_conf_t *) module->config;

    pool = nx_pool_create_child(module->pool);
    while ( (file = NX_DLIST_FIRST(imconf->open_files)) != NULL )
    {
	im_file_input_get_filepos(module, file);
	im_file_input_close(module, file);
    }

    for ( idx = apr_hash_first(pool, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	ASSERT(file != NULL);
	ASSERT(fname != NULL);

	if ( imconf->savepos == TRUE )
	{
	    nx_config_cache_set_int(module->name, file->name, (int) file->filepos);
	    log_debug("module %s saved position %ld for %s",
		      module->name, (long int) file->filepos, file->name);
	}
	apr_hash_set(imconf->files, fname, keylen, NULL);
	apr_pool_destroy(file->pool);
    }
    apr_pool_destroy(pool);

    imconf->event = NULL;
}



static void im_file_pause(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->event != NULL )
    {
	nx_event_remove(imconf->event);
	nx_event_free(imconf->event);
	imconf->event = NULL;
    }
}



static void im_file_resume(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->event != NULL )
    {
	nx_event_remove(imconf->event);
	nx_event_free(imconf->event);
	imconf->event = NULL;
    }
    im_file_add_event(module, FALSE);
}



static void im_file_event(nx_module_t *module, nx_event_t *event)
{
    ASSERT(event != NULL);

    switch ( event->type )
    {
	case NX_EVENT_READ:
	    im_file_read(module);
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}


extern nx_module_exports_t nx_module_exports_im_file;

NX_MODULE_DECLARATION nx_im_file_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    NULL,			// capabilities
    im_file_config,		// config
    im_file_start,		// start
    im_file_stop, 		// stop
    im_file_pause,		// pause
    im_file_resume,		// resume
    NULL,			// init
    NULL,			// shutdown
    im_file_event,		// event
    NULL,			// info
    &nx_module_exports_im_file, //exports
};
