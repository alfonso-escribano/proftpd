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

module wrap2_ldap_module;

struct ldapstore_key {
  const char *subject;

  /* Key data */
  char *key_data;
  uint32_t key_datalen;
};


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
  char **vals = NULL;
  array_header *clients_list = NULL;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(ldaptab->tab_pool);

/* Find the cmdtable for the ldap_ssh_publickey_lookup command. */
  ldap_cmdtab = pr_stash_get_symbol(PR_SYM_HOOK, "ldap_wrap2_clients_lookup",
    NULL, NULL);
  if (ldap_cmdtab == NULL) {
    wrap2_log("unable to find LDAP hook symbol 'ldap_wrap2_clients_lookup'");
    errno = EPERM;
    return NULL;
  }

  ldap_cmd = pr_cmd_alloc(tmp_pool, 1, name);

  ldap_res = pr_module_call(ldap_cmdtab->m, ldap_cmdtab->handler, ldap_cmd);
  if (ldap_res == NULL ||
      MODRET_ISERROR(ldap_res)) {
      wrap2_log("error performing LDAP search");
    destroy_pool(tmp_pool);
    errno = EPERM;
    return NULL;
  }

  ldap_data = (array_header *) ldap_res->data;
  vals = (char **) ldap_data->elts;
  
  if (ldap_data->nelts < 1) {
    wrap2_log("LDAP search returned zero results");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;

  } else {
    wrap2_log("LDAP search returned%d %s", ldap_data->nelts,ldap_data->nelts != 1 ? "addresses" : "address");
  }

  clients_list = make_array(ldaptab->tab_pool, ldap_data->nelts, sizeof(char *));

  /* Iterate through each returned row.  If there are commas or whitespace
   * in the row, parse them as separate client names.  Otherwise, a comma-
   * or space-delimited list of names will be treated as a single name, and
   * violate the principle of least surprise for the site admin.
   */

  for (i = 0; i < ldap_data->nelts; i++) {
    char *ptr;

    if (vals[i] == NULL) {
      continue;
    }

    ptr = strpbrk(vals[i], ", \t");
    if (ptr != NULL) {
      char *dup = pstrdup(ldaptab->tab_pool, vals[i]);
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
        vals[i]);
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
  pool *tmp_pool = NULL;
  cmdtable *ldap_cmdtab = NULL;
  cmd_rec *ldap_cmd = NULL;
  modret_t *ldap_res = NULL;
  array_header *ldap_data = NULL;
  char *query = NULL, **vals = NULL;
  array_header *options_list = NULL;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(ldaptab->tab_pool);

  query = ((char **) ldaptab->tab_data)[WRAP2_SQL_OPTION_QUERY_IDX];

  /* The options-query is not necessary.  Skip if not present. */
  if (!query) {
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Find the cmdtable for the ldap_lookup command. */
  ldap_cmdtab = pr_stash_get_symbol(PR_SYM_HOOK, "ldap_lookup", NULL, NULL);
  if (ldap_cmdtab == NULL) {
    wrap2_log("error: unable to find SQL hook symbol 'ldap_lookup': "
      "perhaps your proftpd.conf needs 'LoadModule mod_ldap.c'?");
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Prepare the SELECT query. */
  ldap_cmd = ldap_cmd_create(tmp_pool, 3, "ldap_lookup", query, name);

  /* Call the handler. */
  ldap_res = pr_module_call(ldap_cmdtab->m, ldap_cmdtab->handler, ldap_cmd);

  /* Check the results. */
  if (!ldap_res) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_ldap.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  if (MODRET_ISERROR(ldap_res)) {
    wrap2_log("error processing SQLNamedQuery '%s': "
      "check the mod_ldap.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Construct a single string, concatenating the returned client tokens
   * together.
   */
  ldap_data = (array_header *) ldap_res->data;
  vals = (char **) ldap_data->elts;

  if (ldap_data->nelts < 1) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_ldap.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  options_list = make_array(ldaptab->tab_pool, ldap_data->nelts, sizeof(char *));
  *((char **) push_array(options_list)) = pstrdup(ldaptab->tab_pool, vals[0]);

  if (ldap_data->nelts > 1) {
    register unsigned int i = 0;

    for (i = 1; i < ldap_data->nelts; i++) {
      if (vals[i] == NULL) {
        continue;
      }

      *((char **) push_array(options_list)) = pstrdup(ldaptab->tab_pool,
        vals[i]);
    }
  }

  destroy_pool(tmp_pool);
  return options_list;
}

static wrap2_table_t *ldaptab_open_cb(pool *parent_pool, char *srcinfo) {
  wrap2_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool),
    *tmp_pool = make_sub_pool(parent_pool);
  config_rec *c = NULL;
  char *start = NULL, *finish = NULL, *query = NULL, *clients_query = NULL,
    *options_query = NULL;

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  /* Parse the SELECT query name out of the srcinfo string.  Lookup and
   * store the query in the tab_data area, so that it need not be looked
   * up later.
   *
   * The srcinfo string for this case should look like:
   *  "/<clients-named-query>[/<options-named-query>]"
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

  clients_query = pstrdup(tab->tab_pool, start);

  /* Verify that the named query has indeed been defined.  This is
   * base on how mod_ldap creates its config_rec names.
   */
  query = pstrcat(tmp_pool, "SQLNamedQuery_", clients_query, NULL);

  c = find_config(main_server->conf, CONF_PARAM, query, FALSE);
  if (c == NULL) {
    wrap2_log("error: unable to resolve SQLNamedQuery name '%s'",
      clients_query);
    pr_log_pri(PR_LOG_WARNING, MOD_WRAP2_SQL_VERSION
      ": no such SQLNamedQuery '%s' found, allowing connection", clients_query);

    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  /* Handle the options-query, if present. */
  if (finish) {
    options_query = pstrdup(tab->tab_pool, ++finish);

    query = pstrcat(tmp_pool, "SQLNamedQuery_", options_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, query, FALSE);
    if (c == NULL) {
      wrap2_log("error: unable to resolve SQLNamedQuery name '%s'",
        options_query);
      destroy_pool(tab_pool);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }
  }

  tab->tab_name = pstrcat(tab->tab_pool, "SQL(", srcinfo, ")", NULL);

  tab->tab_data = pcalloc(tab->tab_pool, WRAP2_SQL_NSLOTS * sizeof(char *));
  ((char **) tab->tab_data)[WRAP2_SQL_CLIENT_QUERY_IDX] =
    pstrdup(tab->tab_pool, clients_query);

  ((char **) tab->tab_data)[WRAP2_SQL_OPTION_QUERY_IDX] =
    (options_query ? pstrdup(tab->tab_pool, options_query) : NULL);

  /* Set the necessary callbacks. */
  tab->tab_close = ldaptab_close_cb;
  tab->tab_fetch_clients = ldaptab_fetch_clients_cb;
  tab->tab_fetch_daemons = ldaptab_fetch_daemons_cb;
  tab->tab_fetch_options = ldaptab_fetch_options_cb;

  destroy_pool(tmp_pool);
  return tab;
}




static int ldapstore_verify_user_key(wrap2_keystore_t *store, pool *p,
    const char *user, char *key_data, uint32_t key_datalen) {
  register unsigned int i;
  struct ldapstore_key *key;
  pool *tmp_pool;
  cmdtable *ldap_cmdtab;
  cmd_rec *ldap_cmd;
  modret_t *ldap_res;
  array_header *ldap_data;
  char **values;
  int res;

  /* Find the cmdtable for the ldap_ssh_publickey_lookup command. */
  ldap_cmdtab = pr_stash_get_symbol(PR_SYM_HOOK, "ldap_ssh_publickey_lookup",
    NULL, NULL);
  if (ldap_cmdtab == NULL) {
    (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
      "unable to find LDAP hook symbol 'ldap_ssh_publickey_lookup'");
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(store->keystore_pool);

  ldap_cmd = pr_cmd_alloc(tmp_pool, 1, user);

  ldap_res = pr_module_call(ldap_cmdtab->m, ldap_cmdtab->handler, ldap_cmd);
  if (ldap_res == NULL ||
      MODRET_ISERROR(ldap_res)) {
    (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
      "error performing LDAP search");
    destroy_pool(tmp_pool);

    errno = EPERM;
    return -1;
  }

  ldap_data = (array_header *) ldap_res->data;

  if (ldap_data->nelts == 0) {
    (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
      "LDAP search returned zero results");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;

  } else {
    (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
      "LDAP search returned %d %s", ldap_data->nelts,
      ldap_data->nelts != 1 ? "keys" : "key");
  }

  values = (char **) ldap_data->elts;
  for (i = 0; i < ldap_data->nelts; i++) {
    pr_signals_handle();

    key = ldapstore_get_key_raw(p, values[i]);
    if (key == NULL) {
      key = ldapstore_get_key_rfc4716(p, values[i]);
    }

    if (key == NULL) {
      (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
        "error obtaining SSH2 public key from LDAP data (key %u)", i+1);
      continue;
    }

    res = wrap2_keys_compare_keys(p, key_data, key_datalen, key->key_data,
      key->key_datalen);
    if (res < 0) {
      (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
        "error comparing client-sent user key with LDAP data (key %u): %s",
        i+1, strerror(errno));
      continue;

    } else if (res == FALSE) {
      (void) pr_log_writefile(wrap2_logfd, MOD_WRAP2_LDAP_VERSION,
        "client-sent user key does not match LDAP data (key %u)", i+1);
      continue;
    }

    pr_trace_msg(trace_channel, 10, "found matching public key (row %u) for "
      "user '%s' using LDAP search", i+1, user);
    destroy_pool(tmp_pool);
    return 0;
  }

  destroy_pool(tmp_pool);
  errno = ENOENT;
  return -1;
}

static int ldapstore_close(wrap2_keystore_t *store) {
  /* Nothing to do here. */
  return 0;
}

static wrap2_keystore_t *ldapstore_open(pool *parent_pool,
    int requested_key_type, const char *store_info, const char *user) {
  wrap2_keystore_t *store;
  pool *ldapstore_pool;

  if (requested_key_type != WRAP2_SSH2_USER_KEY_STORE) {
    errno = EPERM;
    return NULL;
  }

  ldapstore_pool = make_sub_pool(parent_pool);
  pr_pool_tag(ldapstore_pool, "WRAP2 LDAP-based Keystore Pool");

  store = pcalloc(ldapstore_pool, sizeof(wrap2_keystore_t));
  store->keystore_pool = ldapstore_pool;
  store->store_ktypes = WRAP2_SSH2_USER_KEY_STORE;
  store->verify_user_key = ldapstore_verify_user_key;
  store->store_close = ldapstore_close;

  return store;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void wrap2ldap_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_wrap2_ldap.c", (const char *) event_data) == 0) {
    wrap2_keystore_unregister_store("ldap", WRAP2_SSH2_USER_KEY_STORE);
    pr_event_unregister(&wrap2_ldap_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int wrap2ldap_init(void) {
  wrap2_keystore_register_store("ldap", ldapstore_open,
    WRAP2_SSH2_USER_KEY_STORE);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&wrap2_ldap_module, "core.module-unload",
    wrap2ldap_mod_unload_ev, NULL);
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
  wrap2ldap_init,

  /* Module child initialization function */
  NULL,

  /* Module version */
  MOD_WRAP2_LDAP_VERSION
};
