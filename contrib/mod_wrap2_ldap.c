/*
 * ProFTPD: mod_wrap2_ldap -- LDAP backend module for retrieving authorized keys
 *
 * Copyright (c) 2010 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, the respective copyright holders give permission
 * to link this program with OpenSSL, and distribute the resulting
 * executable, without including the source code for OpenSSL in the source
 * distribution.
 */

#include "conf.h"
#include "privs.h"
#include "mod_wrap2.h"

#define MOD_WRAP2_LDAP_VERSION		"mod_wrap2_ldap/0.1"


#define WRAP2_LDAP_NSLOTS		2
#define WRAP2_LDAP_CLIENT_ATTR_IDX	0
#define WRAP2_LDAP_OPTION_ATTR_IDX	1


module wrap2_ldap_module;

static cmd_rec *ldap_cmd_create(pool *parent_pool, int argc, ...) {
  pool *cmd_pool = NULL;
  cmd_rec *cmd = NULL;
  register unsigned int i = 0;
  va_list argp;

  cmd_pool = make_sub_pool(parent_pool);
  cmd = (cmd_rec *) pcalloc(cmd_pool, sizeof(cmd_rec));
  cmd->pool = cmd_pool;

  cmd->argc = argc;
  cmd->argv = (char **) pcalloc(cmd->pool, argc * sizeof(char *));

  /* Hmmm... */
  cmd->tmp_pool = cmd->pool;

  va_start(argp, argc);
  for (i = 0; i < argc; i++)
    cmd->argv[i] = va_arg(argp, char *);
  va_end(argp);

  return cmd;
}


static int ldaptab_close_cb(wrap2_table_t *ldaptab) {
  return 0;
}

static array_header *ldaptab_fetch_clients_cb(wrap2_table_t *ldaptab,
    const char *name) {
  register unsigned int i;
  pool *tmp_pool = NULL;
  cmdtable *ldap_cmdtab = NULL;
  cmd_rec *ldap_cmd = NULL;
  modret_t *ldap_res = NULL;
  array_header *ldap_data = NULL;
  char *attr = NULL, **values = NULL;
  array_header *clients_list = NULL;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(ldaptab->tab_pool);


  attr = ((char **) ldaptab->tab_data)[WRAP2_LDAP_CLIENT_ATTR_IDX];

/* Find the cmdtable for the ldap_ssh_publickey_lookup command. */
  ldap_cmdtab = pr_stash_get_symbol(PR_SYM_HOOK, "ldap_wrap2_clients_lookup",
    NULL, NULL);
  if (ldap_cmdtab == NULL) {
    wrap2_log("unable to find LDAP hook symbol 'ldap_wrap2_clients_lookup'");
    errno = EPERM;
    return NULL;
  }
  /* Prepare the users query. */
  ldap_cmd = ldap_cmd_create(tmp_pool, 3, "ldap_lookup", attr, name);


  ldap_res = pr_module_call(ldap_cmdtab->m, ldap_cmdtab->handler, ldap_cmd);
  if (ldap_res == NULL ||
      MODRET_ISERROR(ldap_res)) {
      wrap2_log("error performing LDAP search");
    destroy_pool(tmp_pool);
    errno = EPERM;
    return NULL;
  }

  ldap_data = (array_header *) ldap_res->data;

  values = (char **) ldap_data->elts;
  
  if (ldap_data->nelts < 1) {
    wrap2_log("LDAP search returned zero results");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  } else {
    wrap2_log("LDAP search returned %d %s", ldap_data->nelts,ldap_data->nelts != 1 ? "addresses" : "address");
  }

  clients_list = make_array(ldaptab->tab_pool, ldap_data->nelts, sizeof(char *));

  /* Iterate through each returned row.  If there are commas or whitespace
   * in the row, parse them as separate client names.  Otherwise, a comma-
   * or space-delimited list of names will be treated as a single name, and
   * violate the principle of least surprise for the site admin.
   */

  for (i = 0; i < ldap_data->nelts; i++) {
    char *ptr;

    if (values[i] == NULL) {
      continue;
    }

    ptr = strpbrk(values[i], ", \t");
    if (ptr != NULL) {
      char *dup = pstrdup(ldaptab->tab_pool, values[i]);
      char *word;

      while ((word = pr_str_get_token(&dup, ", \t")) != NULL) {
        size_t wordlen;

        pr_signals_handle();

        wordlen = strlen(word);
        if (wordlen == 0)
          continue;

        /* Remove any trailing comma */
        if (word[wordlen-1] == ',')
          word[wordlen-1] = '\0';

        *((char **) push_array(clients_list)) = word;

        /* Skip redundant whitespaces */
        while (*dup == ' ' ||
               *dup == '\t') {
          pr_signals_handle();
          dup++;
        }
      }

    } else {
      *((char **) push_array(clients_list)) = pstrdup(ldaptab->tab_pool,
        values[i]);
    }
  }

  destroy_pool(tmp_pool);
  return clients_list;
}

static array_header *ldaptab_fetch_daemons_cb(wrap2_table_t *ldaptab,
    const char *name) {
  array_header *daemons_list = make_array(ldaptab->tab_pool, 1, sizeof(char *));

  /* Simply return the service name we're given. */
  *((char **) push_array(daemons_list)) = pstrdup(ldaptab->tab_pool, name);

  return daemons_list;
}

static array_header *ldaptab_fetch_options_cb(wrap2_table_t *ldaptab,
    const char *name) {
  array_header *options_list = NULL;

  return options_list;
}

static wrap2_table_t *ldaptab_open_cb(pool *parent_pool, char *srcinfo) {
  wrap2_table_t *tab = NULL;
  char *start = NULL, *finish = NULL, *clients_attr = NULL, *options_attr = NULL;

  pool *tab_pool = make_sub_pool(parent_pool),
    *tmp_pool = make_sub_pool(parent_pool);

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  /* Parse the ldap attribute query name out of the srcinfo string.  Lookup and
   * store the query in the tab_data area, so that it need not be looked
   * up later.
   *
   * The srcinfo string for this case should look like:
   *  "/<clients-attribute>[/<options-attribute>]"
   */

  start = strchr(srcinfo, '/');
  if (start == NULL) {
    wrap2_log("error: badly formatted source info '%s'", srcinfo);
    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  /* Find the next slash. */
  finish = strchr(++start, '/');

  if (finish)
    *finish = '\0';

  clients_attr = pstrdup(tab->tab_pool, start);

  /* Handle the options-attr, if present. */
  if (finish) {
    options_attr = pstrdup(tab->tab_pool, ++finish);
  }

  tab->tab_name = pstrcat(tab->tab_pool, "LDAP(", srcinfo, ")", NULL);

  tab->tab_data = pcalloc(tab->tab_pool, WRAP2_LDAP_NSLOTS * sizeof(char *));
  ((char **) tab->tab_data)[WRAP2_LDAP_CLIENT_ATTR_IDX] =
    pstrdup(tab->tab_pool, clients_attr);

  ((char **) tab->tab_data)[WRAP2_LDAP_OPTION_ATTR_IDX] =
    (options_attr ? pstrdup(tab->tab_pool, options_attr) : NULL);

  tab->tab_name = pstrcat(tab->tab_pool, "SQL(", srcinfo, ")", NULL);

  /* Set the necessary callbacks. */
  tab->tab_close = ldaptab_close_cb;
  tab->tab_fetch_clients = ldaptab_fetch_clients_cb;
  tab->tab_fetch_daemons = ldaptab_fetch_daemons_cb;
  tab->tab_fetch_options = ldaptab_fetch_options_cb;

  destroy_pool(tmp_pool);
  return tab;
}




/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void ldaptab_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_wrap2_ldap.c", (const char *) event_data) == 0) {
    pr_event_unregister(&wrap2_ldap_module, NULL, NULL);
    wrap2_unregister("ldap");
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int ldaptab_init(void) {
  wrap2_register("ldap", ldaptab_open_cb);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&wrap2_ldap_module, "core.module-unload",
    ldaptab_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module wrap2_ldap_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "wrap2_ldap",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ldaptab_init,

  /* Module child initialization function */
  NULL,

  /* Module version */
  MOD_WRAP2_LDAP_VERSION
};
