# How to Use the MySQL Audit Tool Plugin

This page explains how to install and run the `audittool` MySQL Shell plugin, create audit filters through the wizard, and assign filters to MySQL accounts.

The plugin is an independent community tool. It is not part of MySQL, MySQL Shell, Oracle, or an official MySQL source tree.

## What the plugin does

The plugin adds this MySQL Shell command:

```python
audittool.start.wizard()
```

The wizard helps you:

- Check whether MySQL Enterprise Audit is available through either the audit log component or the legacy audit log plugin.
- Check recommended audit settings.
- Create audit filter JSON without hand-writing the JSON.
- Display existing filters as raw rows, pretty-printed JSON, or high-level summaries.
- Assign filters to users, hosts, or the `%` default fallback account.
- Classify accounts by privilege level before assigning filters.
- Prevent assigning a second filter to an account that already has one.
- Remove filter assignments and delete unused filters.

## Requirements

You need:

- MySQL Shell with Python plugin support.
- Access to a MySQL server with MySQL Enterprise Audit installed.
- A MySQL account with privileges to manage audit filters. In most deployments this means `AUDIT_ADMIN` or an equivalent administrative account.
- The audit filter tables installed, normally `mysql.audit_log_filter` and `mysql.audit_log_user`.

The plugin supports both:

- MySQL Enterprise Audit component: `file://component_audit_log`
- Legacy MySQL Enterprise Audit plugin: `audit_log`

For MySQL 9.7 and newer, the audit log component is preferred because the audit log plugin is deprecated.

## Install the plugin

Create a plugin folder under the MySQL Shell user plugin directory.

On Linux or macOS:

```bash
mkdir -p ~/.mysqlsh/plugins/audittool_plugin
cp init.py ~/.mysqlsh/plugins/audittool_plugin/init.py
cp wizard.py ~/.mysqlsh/plugins/audittool_plugin/wizard.py
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force "$env:APPDATA\MySQL\mysqlsh\plugins\audittool_plugin"
Copy-Item .\init.py "$env:APPDATA\MySQL\mysqlsh\plugins\audittool_plugin\init.py"
Copy-Item .\wizard.py "$env:APPDATA\MySQL\mysqlsh\plugins\audittool_plugin\wizard.py"
```

Expected layout:

```text
~/.mysqlsh/plugins/audittool_plugin/
├── init.py
└── wizard.py
```

Restart MySQL Shell after copying the files. MySQL Shell loads plugins at startup.

## Connect and start the wizard

Start MySQL Shell in Python mode and connect to the target server:

```bash
mysqlsh --py user@host:3306
```

Or start MySQL Shell and connect interactively:

```text
\py
\connect user@host:3306
```

Run the wizard:

```python
audittool.start.wizard()
```

## Startup checks

When the wizard starts, it checks for MySQL Enterprise Audit.

For the component path, it checks for this row:

```sql
SELECT *
FROM mysql.component
WHERE component_urn = 'file://component_audit_log';
```

For the legacy plugin path, it checks for the active `audit_log` plugin:

```sql
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME = 'audit_log'
  AND PLUGIN_STATUS = 'ACTIVE';
```

It also checks that the filter metadata tables exist:

```sql
mysql.audit_log_filter
mysql.audit_log_user
```

If either the audit component or audit plugin is installed, and the audit filter tables are present, the wizard continues.

## Recommended audit settings

After the audit installation check, the wizard reports recommended settings.

For the legacy audit plugin, it recommends:

```text
audit_log_format = JSON
audit_log_format_unix_timestamp = ON
```

For the audit component, audit log output is JSON format, so the wizard only checks the component-style Unix timestamp setting:

```text
audit_log.format_unix_timestamp = ON
```

The wizard only reports these recommendations. It does not change server settings.

## Main menu

After startup, the wizard shows:

```text
What do you want to do?
1 - Show audit filters
2 - Create a new audit filter
3 - Delete an audit filter
4 - Show users and filter
5 - Add users to an audit filter
6 - Delete users from an audit filter
7 - Quit
```

## Show audit filters

Choose option `1` from the main menu.

The display submenu is:

```text
Show audit filters
1 - Current as-is
2 - Pretty print JSON
3 - High level description of each filter with list of users using it
4 - Return
```

Use `Current as-is` when you want to see the raw rows from `mysql.audit_log_filter`.

Use `Pretty print JSON` when you want readable JSON for each stored filter.

Use `High level description` when you want a compact explanation of what each filter logs and which users are assigned to it.

Example summary output:

```text
1. log_all
   Users: % (default fallback)
   Description: logs everything

2. admin_changes
   Users: root@localhost, dba@%
   Description: inclusive filter: logs only matching classes/events; general: events=status; SQL commands=create_user,grant,revoke; query text replaced with query_digest
```

## Create a new audit filter

Choose option `2` from the main menu.

The creation menu supports multi-select entries. For example, enter `2,4,7` to combine connections, failed operations, and user/role/privilege changes into one filter.

```text
What types actions do you wish to collect in the audit log?
Enter one or more selections separated by commas, for example: 2,4,7,8
1  - Log Everything
2  - Connections
3  - Non-SSL TCP connection attempts
4  - Failed operations
5  - Sensitive table access / table DML
6  - DDL changes
7  - User, role, and privilege changes
8  - Audit administration changes
9  - Administrative server commands
10 - Stored code / scheduled event changes
11 - Bulk import/export and data movement
12 - Replication / topology changes
13 - Custom command group from performance_schema.setup_instruments
14 - Application audit messages
15 - Return
```

### Important selection rules

`1 - Log Everything` stands on its own. Do not combine it with other choices.

Valid examples:

```text
1
2,4,7
5,6,8,9
```

Invalid example:

```text
1,4
```

### Filter types

#### 1 - Log Everything

Creates a filter equivalent to:

```json
{
  "filter": {
    "log": true
  }
}
```

This is commonly assigned to `% (default fallback)` when you want to audit all accounts that do not have a more specific filter.

#### 2 - Connections

Creates a connection-event filter. Depending on the submenu selections, it can log:

- all connections
- failed connections
- successful connections
- connect and disconnect events
- `change_user` events

#### 3 - Non-SSL TCP connection attempts

Creates a connection filter for TCP/IP connection attempts that are not using the SSL connection type.

Use this for compliance checks where encrypted connections are expected.

#### 4 - Failed operations

Creates a general/status filter for unsuccessful operations, using nonzero MySQL error codes.

#### 5 - Sensitive table access / table DML

Prompts for one or more schema/table targets and one or more table-access actions:

- read
- insert
- update
- delete

Use this for sensitive tables such as payroll, security, financial, or PII-related tables.

The wizard validates that the schema and table exist before building the filter.

#### 6 - DDL changes

Prompts for DDL command types such as create, alter, drop, rename, and related schema/object changes.

Use this to audit structural changes to databases and objects.

#### 7 - User, role, and privilege changes

Creates a security administration filter for account, role, grant, and revoke operations.

Typical commands include:

- create user
- alter user
- drop user
- create role
- drop role
- grant
- revoke
- default role changes

#### 8 - Audit administration changes

Creates a filter for audit-related administration, such as component/plugin installation changes and SET-style administration. This helps track changes that may affect audit behavior.

#### 9 - Administrative server commands

Creates a filter for server-level administrative commands such as SET, FLUSH, RESET, KILL, SHUTDOWN, install/uninstall plugin, and install/uninstall component where available.

#### 10 - Stored code / scheduled event changes

Creates a filter for changes to stored routines, functions, triggers, and scheduled events.

Use this to monitor persistence mechanisms and database-side code changes.

#### 11 - Bulk import/export and data movement

Creates a filter for bulk data movement patterns such as load, import, export, and related commands where available.

#### 12 - Replication / topology changes

Creates a filter for replication, source/replica, clone, and group replication administration commands where available.

#### 13 - Custom command group from performance_schema.setup_instruments

Queries available SQL command instruments from:

```sql
SELECT NAME
FROM performance_schema.setup_instruments
WHERE NAME LIKE 'statement/sql/%'
ORDER BY NAME;
```

The wizard lets you select commands and builds a custom `general_sql_command.str` filter from those choices.

#### 14 - Application audit messages

Creates a filter for application-generated audit messages from the audit message component path, including user and internal message events where available.

## Assign users to filters

Choose option `5` from the main menu.

The wizard lists accounts from `mysql.user` plus the special `% (default fallback)` audit account.

Example account list:

```text
Available MySQL accounts
#    User@Host                         Locked  Audit filter(s)             State       Classification
---- --------------------------------- ------- --------------------------- ----------- ---------------------------
  1  % (default fallback)              -       -                           available   Default audit fallback
  2  app@%                             N       -                           available   Schema/object privileged
  3  root@localhost                    N       admin_changes               assigned    Admin / high privilege
```

### One filter per account

A user account can have only one audit filter assignment. If an account already has a filter, the wizard shows it as `assigned` and blocks it from being selected for another filter.

To change the filter for an assigned user:

1. Use option `6 - Delete users from an audit filter`.
2. Remove the existing assignment.
3. Use option `5 - Add users to an audit filter`.
4. Assign the new filter.

### The `%` default fallback account

`%` is not a normal MySQL user account. In audit filtering, `%` is the default fallback assignment for any account that does not have its own explicit audit filter.

For example:

```sql
SELECT audit_log_filter_set_user('%', 'log_all');
```

The wizard displays this as:

```text
% (default fallback)
```

Like normal accounts, `%` can only be assigned to one filter at a time.

## Show users and filters

Choose option `4` from the main menu.

The wizard shows current audit user assignments and includes account classification details. This is useful before changing assignments because it identifies high-privilege or system/internal accounts.

Classification examples:

- `System/internal account`
- `Admin / high privilege`
- `Security administration`
- `Global privileged`
- `Schema/object privileged`
- `Role-backed account`
- `Login only / low direct grants`
- `Default audit fallback`

These classifications are advisory. Review the actual privileges before making policy decisions.

## Delete user filter assignments

Choose option `6` from the main menu.

The wizard lists assigned accounts and removes assignments through:

```sql
SELECT audit_log_filter_remove_user('user@host');
```

For the default fallback account, it uses:

```sql
SELECT audit_log_filter_remove_user('%');
```

## Delete audit filters

Choose option `3` from the main menu.

The wizard separates filters into:

- filters with assigned users, which cannot be deleted yet
- filters with no assigned users, which can be removed

Remove user assignments first before deleting a filter.

The wizard removes filters through:

```sql
SELECT audit_log_filter_remove_filter('filter_name');
```

## Common workflows

### Audit everything by default

1. Start the wizard.
2. Choose `2 - Create a new audit filter`.
3. Choose `1 - Log Everything`.
4. Name the filter, for example `log_all`.
5. Choose `5 - Add users to an audit filter`.
6. Select `log_all`.
7. Select `% (default fallback)`.

Equivalent SQL shape:

```sql
SELECT audit_log_filter_set_filter('log_all', '{ "filter": { "log": true } }');
SELECT audit_log_filter_set_user('%', 'log_all');
```

### Audit DBAs more heavily than application users

1. Create a broad default filter for `%`, such as failed operations plus security changes.
2. Create a second DBA-focused filter for connections, DDL, privilege changes, audit administration, and administrative server commands.
3. Assign the DBA-focused filter directly to DBA accounts.
4. Leave `%` as the fallback for all other accounts.

### Audit sensitive table reads

1. Choose `2 - Create a new audit filter`.
2. Select `5 - Sensitive table access / table DML`.
3. Select `read`.
4. Enter the target schema and table.
5. Enable query digest masking when prompted if you do not want full SQL text with literals in the audit log.
6. Assign the filter to the relevant application or DBA accounts.

### Audit account and privilege changes

1. Choose `2 - Create a new audit filter`.
2. Select `7 - User, role, and privilege changes`.
3. Consider enabling query digest masking.
4. Assign the filter to `%` or to high-privilege accounts.

## Troubleshooting

### The command `audittool.start.wizard()` is not found

Check that the plugin files are in the right folder and restart MySQL Shell.

Expected folder:

```text
~/.mysqlsh/plugins/audittool_plugin/init.py
~/.mysqlsh/plugins/audittool_plugin/wizard.py
```

Start MySQL Shell with debug logging if plugin loading fails:

```bash
mysqlsh --log-level=debug --py
```

Then check the MySQL Shell application log for plugin load errors.

### The wizard says Enterprise Audit is not installed

Check component installation:

```sql
SELECT * FROM mysql.component;
```

Look for:

```text
file://component_audit_log
```

For the legacy plugin path, check:

```sql
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME = 'audit_log';
```

### The wizard says audit filter tables are missing

The filter tables are normally installed by the Enterprise Audit installation script. For the audit component, the MySQL 9.7 installation script is commonly named:

```text
audit_log_component_filter_install.sql
```

Run the appropriate Enterprise Audit installation procedure for your MySQL version and edition.

### A user is not selectable when assigning a filter

The account probably already has an audit filter assignment. Remove the existing assignment first using option `6 - Delete users from an audit filter`.

### `% (default fallback)` is not selectable

The default fallback account already has an audit filter assignment. Remove that assignment first if you want to replace it.

## Safety notes

- Review generated JSON before naming and installing the filter.
- Prefer query digest masking for filters that may capture credentials, tokens, PII, or application literals.
- Be careful assigning `log_all` to `%` on busy systems because audit volume can grow quickly.
- Do not delete filters that are still assigned to users. Remove user assignments first.
- This wizard creates and removes audit filters and user assignments. Test in a non-production environment before using it on production systems.

## Related MySQL documentation

- MySQL Shell plugins: https://dev.mysql.com/doc/mysql-shell/8.4/en/mysql-shell-plugins-create.html
- MySQL Enterprise Audit component installation: https://dev.mysql.com/doc/refman/9.7/en/audit-log-component-installation.html
- Audit log component filtering: https://dev.mysql.com/doc/refman/9.7/en/audit-log-component-filtering.html
- Audit log component filter definitions: https://dev.mysql.com/doc/refman/9.7/en/audit-log-component-filter-definitions.html
- Grant tables: https://dev.mysql.com/doc/refman/9.7/en/grant-tables.html
