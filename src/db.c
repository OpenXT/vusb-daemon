/*
 * Copyright (c) 2015 Assured Information Security, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   db.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:13:27 2015
 *
 * @brief  Database interaction
 *
 * Functions to read/write the policy from/to the database.
 * This file should stay as separate as possible from the main
 * project, to be usable in other programs (like a rule manager)
 */

#include "db.h"

#define db_log(I, ...) { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); }

xcdbus_conn_t *db_xcbus = NULL; /**< A dbus (libxcdbus) handle, initialized by db_init() */

static char*
parse_value(char *node_path, char *key)
{
  char *value;
  char path[128];

  snprintf(path, 128, "%s/%s", node_path, key);
  if (com_citrix_xenclient_db_read_(db_xcbus, DB, DB_OBJ, path, &value))
    return value;

  return NULL;
}

static void
add_pair(char *key, char *value, char ***list)
{
  char *new_key, *new_value;
  int size = 0;

  new_key = malloc(strlen(key) + 1);
  new_value = malloc(strlen(value) + 1);
  strcpy(new_key, key);
  strcpy(new_value, value);

  /* Initialize the list if needed */
  if (*list == NULL)
  {
    *list = malloc(sizeof(char*));
    **list = NULL;
  }
  /* Check the size of the list */
  while (*(*list + size) != NULL)
    size++;

  /* "size" is the size of the list - 1. Add 2 slots, replace the old
   * NULL terminator with the key, then add the value and NULL */
  *list = realloc(*list, (size + 3) * sizeof(char*));
  *(*list + size) = new_key;
  *(*list + size + 1) = new_value;
  *(*list + size + 2) = NULL;
}

static void
parse_udev_sysattr_or_property(char *node_path, char *rul, rule_t *res, bool sysattr)
{
  char **ru, **ru_list = NULL;
  char *value;
  char subnode_path[128];

  snprintf(subnode_path, 128, "%s/%s", node_path, rul);
  if (com_citrix_xenclient_db_list_(db_xcbus, DB, DB_OBJ, subnode_path, &ru_list)) {
    ru = ru_list;
    while (*ru != NULL) {
      value = parse_value(subnode_path, *ru);
      if (value != NULL) {
        if (sysattr)
          add_pair(*ru, value, &res->dev_sysattrs);
        else
          add_pair(*ru, value, &res->dev_properties);
        g_free(value);
      }
      ru++;
    }
    g_strfreev(ru_list);
    ru_list = NULL;
  }
}

static void
parse_device(char *rule_path, char *rule, rule_t *res)
{
  char **rul, **rul_list;
  char *value;
  char *serial = NULL;
  char node_path[128];

  snprintf(node_path, 128, "%s/%s", rule_path, rule);
  if (com_citrix_xenclient_db_list_(db_xcbus, DB, DB_OBJ, node_path, &rul_list)) {
    rul = rul_list;
    while (*rul != NULL) {
      if        (!strcmp(*rul, NODE_SYSATTR)) {
        parse_udev_sysattr_or_property(node_path, *rul, res, true);
      } else if (!strcmp(*rul, NODE_PROPERTY)) {
        parse_udev_sysattr_or_property(node_path, *rul, res, false);
      } else if (!strcmp(*rul, NODE_MOUSE)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= MOUSE;
          else
            res->dev_type |= MOUSE;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_KEYBOARD)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= KEYBOARD;
          else
            res->dev_type |= KEYBOARD;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_AUDIO)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= AUDIO;
          else
            res->dev_type |= AUDIO;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_NIC)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= NIC;
          else
            res->dev_type |= NIC;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_BLUETOOTH)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= BLUETOOTH;
          else
            res->dev_type |= BLUETOOTH;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_GAME_CONTROLLER)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= GAME_CONTROLLER;
          else
            res->dev_type |= GAME_CONTROLLER;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_MASS_STORAGE)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= MASS_STORAGE;
          else
            res->dev_type |= MASS_STORAGE;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_OPTICAL)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= OPTICAL;
          else
            res->dev_type |= OPTICAL;
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_VENDOR_ID)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          res->dev_vendorid = strtol(value, NULL, 16);
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_DEVICE_ID)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          res->dev_deviceid = strtol(value, NULL, 16);
          g_free(value);
        }
      } else if (!strcmp(*rul, NODE_SERIAL)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          serial = malloc(strlen(value) + 1);
          strcpy(serial,value);
          res->dev_serial = serial;
          g_free(value);
        }
      } else db_log(DB_LOG_ERR, "Unknown Device attribute %s", *rul);
      rul++;
    }
    g_strfreev(rul_list);
  }
}

static void
parse_vm(char *rule_path, char *rule, rule_t *res)
{
  char **rul, **rul_list;
  char *value;
  char node_path[128];

  snprintf(node_path, 128, "%s/%s", rule_path, rule);
  if (com_citrix_xenclient_db_list_(db_xcbus, DB, DB_OBJ, node_path, &rul_list)) {
    rul = rul_list;
    while (*rul != NULL) {
      if (!strcmp(*rul, NODE_UUID)) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          res->vm_uuid = malloc(strlen(value) + 1);
          strcpy(res->vm_uuid, value);
          g_free(value);
        }
      } else {
        db_log(DB_LOG_ERR, "Unknown VM attribute %s", *rul);
      }
      rul++;
    }
    g_strfreev(rul_list);
  }
}

static rule_t*
parse_rule(char *rule_node)
{
  char **rule, **rule_list;
  char rule_path[64];
  char *value;
  rule_t* res;

  res = malloc(sizeof(rule_t));
  memset(res, 0, sizeof(rule_t));
  res->pos = strtol(rule_node, NULL, 10);
  snprintf(rule_path, 64, "%s/%s", NODE_RULES, rule_node);
  if (com_citrix_xenclient_db_list_(db_xcbus, DB, DB_OBJ, rule_path, &rule_list)) {
    rule = rule_list;
    while (*rule != NULL) {
      if        (!strcmp(*rule, NODE_COMMAND)) {
        value = parse_value(rule_path, *rule);
        if (value != NULL) {
          res->cmd = policy_parse_command_string(value);
          g_free(value);
        }
      } else if (!strcmp(*rule, NODE_DESCRIPTION)) {
        value = parse_value(rule_path, *rule);
        if (value != NULL) {
          res->desc = malloc(strlen(value) + 1);
          strcpy(res->desc, value);
          g_free(value);
        }
      } else if (!strcmp(*rule, NODE_DEVICE)) {
        parse_device(rule_path, *rule, res);
      } else if (!strcmp(*rule, NODE_VM)) {
        parse_vm(rule_path, *rule, res);
      } else {
        db_log(DB_LOG_ERR, "Unknown rule attribute %s", *rule);
      }
      rule++;
    }
    g_strfreev(rule_list);
  }

  return res;
}

static void
db_write_rule_key(int pos, char *key, char *value)
{
  char path[128];

  snprintf(path, 128, "%s/%d/%s", NODE_RULES, pos, key);
  com_citrix_xenclient_db_write_(db_xcbus, DB, DB_OBJ, path, value);
}

static void
add_rule_to_list(rule_t *rules, rule_t *new_rule)
{
  struct list_head *pos;
  rule_t *rule = NULL;

  list_for_each(pos, &rules->list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->pos > new_rule->pos)
      break;
  }
  if (rule == NULL)
    /* The list is empty. Adding "new_rule" as the first rule. */
    list_add(&new_rule->list, &rules->list);
  else if (rule->pos > new_rule->pos)
    /* "rule" is the first rule bigger than new_rule. Adding
     * "new_rule" just before "rule" */
    /* list_add_tail adds a just before b (yeah, when using a list
     * node as the head, the function names don't make sense anymore) */
    list_add_tail(&new_rule->list, &rule->list);
  else
    /* The new rule is the biggest, adding it after "rule", which is
     * the last (and biggest) rule in the list */
    /* list_add adds a just after b */
    list_add(&new_rule->list, &rule->list);
}

/**
 * Initalize the database bits.
 * This should be called before any other db_ function.
 *
 * @param xcbus_conn An xcdbus open connection
 */
void
db_dbus_init(xcdbus_conn_t *xcbus_conn)
{
  db_xcbus = xcbus_conn;
  /* Wait until all the services we talk to are up */
  xcdbus_wait_service(db_xcbus, "com.citrix.xenclient.db");
}

/**
 * Read the policy from the database
 *
 * @param rules Initialized rule list to store the policy
 */
void
db_read_policy(rule_t *rules)
{
  char **rule_nodes, **rule_nodes_list;
  rule_t *rule;

  if (com_citrix_xenclient_db_list_(db_xcbus, DB, DB_OBJ, NODE_RULES, &rule_nodes_list)) {
    rule_nodes = rule_nodes_list;
    while (*rule_nodes != NULL) {
      rule = parse_rule(*rule_nodes);
      if (rule != NULL)
        add_rule_to_list(rules, rule);
      rule_nodes++;
    }
    g_strfreev(rule_nodes_list);
  }
}

/**
 * Write sysattr or property nodes
 */
static void
write_sysattr_or_properties(int pos, char *node_path, char** map) {
  int index=0;
  char subnode_path[128];

  if (node_path == NULL || map == NULL) return;
  while (map[index] != NULL) {
    snprintf(subnode_path, 128, "%s/%s",
        node_path,
        map[index]);
    db_write_rule_key(pos, subnode_path, map[index+1]);
    index += 2;
  }
}

/**
 * Dump the policy to the database
 *
 * @param rules The list of rules to write
 */
void
db_write_policy(rule_t *rules)
{
  struct list_head *pos;
  rule_t *rule = NULL;
  char value[5];

  com_citrix_xenclient_db_rm_(db_xcbus, DB, DB_OBJ, NODE_RULES);

  list_for_each(pos, &rules->list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->desc != NULL)
      db_write_rule_key(rule->pos, NODE_DESCRIPTION, rule->desc);

    db_write_rule_key(rule->pos, NODE_COMMAND, policy_parse_command_enum(rule->cmd));

    if (rule->dev_type != 0) {
      if (rule->dev_type & KEYBOARD)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_KEYBOARD, "1");
      if (rule->dev_type & MOUSE)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_MOUSE, "1");
      if (rule->dev_type & GAME_CONTROLLER)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_GAME_CONTROLLER, "1");
      if (rule->dev_type & MASS_STORAGE)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_MASS_STORAGE, "1");
      if (rule->dev_type & OPTICAL)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_OPTICAL, "1");
      if (rule->dev_type & NIC)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_NIC, "1");
      if (rule->dev_type & BLUETOOTH)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_BLUETOOTH, "1");
      if (rule->dev_type & AUDIO)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_AUDIO, "1");
    }
    if (rule->dev_not_type != 0) {
      if (rule->dev_not_type & KEYBOARD)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_KEYBOARD, "0");
      if (rule->dev_not_type & MOUSE)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_MOUSE, "0");
      if (rule->dev_not_type & GAME_CONTROLLER)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_GAME_CONTROLLER, "0");
      if (rule->dev_not_type & MASS_STORAGE)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_MASS_STORAGE, "0");
      if (rule->dev_not_type & NIC)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_NIC, "0");
      if (rule->dev_not_type & BLUETOOTH)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_BLUETOOTH, "0");
      if (rule->dev_not_type & AUDIO)
        db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_AUDIO, "0");
    }
    if (rule->dev_vendorid != 0) {
      snprintf(value, 5, "%04X", rule->dev_vendorid);
      db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_VENDOR_ID, value);
    }
    if (rule->dev_deviceid != 0) {
      snprintf(value, 5, "%04X", rule->dev_deviceid);
      db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_DEVICE_ID, value);
    }
    if (rule->dev_serial != NULL) {
      db_write_rule_key(rule->pos, NODE_DEVICE "/" NODE_SERIAL, rule->dev_serial);
    }
    if (rule->dev_sysattrs != NULL) {
      write_sysattr_or_properties(rule->pos,
          NODE_DEVICE "/" NODE_SYSATTR,
          rule->dev_sysattrs);
    }
    if (rule->dev_properties != NULL) {
      write_sysattr_or_properties(rule->pos,
          NODE_DEVICE "/" NODE_PROPERTY,
          rule->dev_properties);
    }
    if (rule->vm_uuid != NULL)
      db_write_rule_key(rule->pos, NODE_VM "/" NODE_UUID, rule->vm_uuid);
  }
}
