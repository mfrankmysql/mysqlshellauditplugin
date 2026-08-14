# Copyright (c) 2026 Mike
# SPDX-License-Identifier: UPL-1.0
#
# This is an independent community MySQL Shell plugin. It is not part of
# MySQL, MySQL Shell, Oracle, or any official MySQL source tree.
#
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the LICENSE file for details.

"""MySQL Enterprise Audit filter wizard for MySQL Shell.

This module registers audittool.start.wizard().
"""


from mysqlsh.plugin_manager import plugin_function
import json


def fetch_session(session=None):

    import mysqlsh
    shell = mysqlsh.globals.shell
    # Check if the user provided a session or there is an active global session
    if session is None:
        session = shell.get_session()
        if session is None:
            print("No session specified. Either pass a session object to this "
                "function or connect the shell to a database.")
            return None
    return session


def sql_string(value):
    """Return value as a SQL single-quoted literal body.

    MySQL string literals escape a single quote by doubling it. This keeps the
    wizard from breaking when names or JSON contain apostrophes. Prefer true
    bind variables if/when this code is moved to an API that supports them.
    """
    return str(value).replace("'", "''")


def is_default_audit_account(username, hostname=None):
    """Return True for the audit default account represented by %.

    This is not a real mysql.user row. MySQL audit filtering uses the single
    account name % as a fallback for accounts that have no explicit assignment.
    In mysql.audit_log_user this is stored as USER='%' and an empty HOST.
    """
    return str(username) == '%' and (hostname is None or str(hostname) == '')


def normalize_audit_account_key(username, hostname=None):
    """Normalize mysql.audit_log_user account keys for lookups."""
    if is_default_audit_account(username, hostname):
        return ('%', '')
    return (str(username), '' if hostname is None else str(hostname))


def audit_account_function_arg(username, hostname=None):
    """Return the account string expected by audit filter SQL functions."""
    if is_default_audit_account(username, hostname):
        return '%'
    return str(username) + '@' + str(hostname)


def audit_account_display(username, hostname=None):
    """Return a human-friendly audit account label."""
    if is_default_audit_account(username, hostname):
        return '% (default fallback)'
    return str(username) + '@' + str(hostname)


def default_fallback_account(assigned_filters=None):
    """Pseudo account row for the global audit fallback."""
    account = {
        'user': '%',
        'host': '',
        'userhost': '% (default fallback)',
        'account_locked': '-',
        'static_privs': [],
        'dynamic_privs': [],
        'db_priv_count': 0,
        'table_priv_count': 0,
        'column_priv_count': 0,
        'routine_priv_count': 0,
        'roles': [],
        'default_roles': [],
        'assigned_filters': assigned_filters or [],
        'classification': 'Default audit fallback',
        'classification_reason': 'applies to accounts without explicit audit filter assignment',
    }
    return account


def check_user_input_yes(prompt):
    """Return True only for Y/y. Return False for N/n."""
    return check_user_input_y_n(prompt) == 'Y'


def filter_json(filter_doc):
    """Serialize and validate an audit filter definition."""
    return json.dumps(filter_doc, separators=(',', ':'))


def install_audit_filter(session, shell, filt_name, filter_doc):
    """Create or replace an audit filter by using the audit SQL function."""
    fjson = filter_json(filter_doc)
    fstmt = "SELECT audit_log_filter_set_filter('" + sql_string(filt_name) + "','" + sql_string(fjson) + "')"
    print(fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
        print('Failed to create')


def remove_audit_filter(session, shell, filt_name):
    """Remove an audit filter by using the audit SQL function."""
    stmt = "SELECT audit_log_filter_remove_filter('" + sql_string(filt_name) + "')"
    print(stmt)
    r = session.run_sql(stmt)
    shell.dump_rows(r)


def check_user_name(uname, uhost, session=None):
    session = fetch_session(session)
    if session is None:
        return False

    if is_default_audit_account(uname, uhost):
        return True

    stmt = (
        "select count(*) as cname from mysql.user "
        "where user='" + sql_string(uname) + "' and host='" + sql_string(uhost) + "'"
    )
    r = session.run_sql(stmt)
    row = r.fetch_one()
    return row is not None and int(row.get_field('cname')) > 0

def read_wizard_input(prompt):
    """Read interactive input using a MySQL Shell-friendly prompt.

    MySQL Shell can render input(prompt) awkwardly in Python mode, especially
    when the prompt is followed immediately by typed input. Printing the prompt
    first and then reading from a short marker keeps menu output readable.
    """
    if prompt:
        print(prompt)
    return input("> ")


def check_user_input_pos_int(prompt):
    intnotok=True
    val=0
    while intnotok == True:
        input_str = read_wizard_input(prompt)
        x = input_str.strip()
        if x.isalpha():
            intnotok=True
            print("Please re-enter. Input must be digit.") 
        elif x.isdigit():
            intnotok=False
            val=int(x)
        else:
            intnotok=True
            print("Please re-enter. Input must be digit.") 
    return str(val)

def check_user_input_y_n(prompt):
    charnotok=True
    val='N'
    while charnotok == True:
        input_str = read_wizard_input(prompt)
        if(input_str.isascii()):
            x = input_str.strip().upper()
            if (x == 'Y'):
                val='Y'
                charnotok=False
            elif (x == 'N'):
                val='N'
                charnotok=False
            else:
                charnotok=True
                print("Please re-enter. Input must be Y, y, N, n") 
        else:
            charnotok=True
            print("Please re-enter. Input must be Y, y, N, n") 
    return val

def fetch_audit_filter_rows(session):
    """Return audit filter rows as dictionaries with name and filter_json text."""
    rows = run_sql_fetch_all(
        session,
        "select name as filter_name, filter as filter_json from mysql.audit_log_filter order by name"
    )
    result = []
    for row in rows:
        result.append({
            'name': str(row_value(row, 'filter_name', 0, '')),
            'filter_json': str(row_value(row, 'filter_json', 1, '')),
        })
    return result


def fetch_audit_filter_users_by_filter(session):
    """Return a map of audit filter name to assigned audit account labels."""
    result = {}
    if not table_exists(session, 'mysql', 'audit_log_user'):
        return result

    rows = run_sql_fetch_all(
        session,
        "select user, host, filtername from mysql.audit_log_user order by filtername, user, host"
    )
    for row in rows:
        user_name = str(row_value(row, 'user', 0, ''))
        host_name = str(row_value(row, 'host', 1, ''))
        filter_name = str(row_value(row, 'filtername', 2, ''))
        result.setdefault(filter_name, []).append(audit_account_display(user_name, host_name))
    return result


def parse_filter_json(filter_text):
    """Parse a stored audit filter JSON document."""
    try:
        return json.loads(filter_text), None
    except Exception as exc:
        return None, str(exc)


def iter_audit_classes(filter_body):
    """Yield class dictionaries from an audit filter body."""
    classes = filter_body.get('class')
    if classes is None:
        return []
    if isinstance(classes, list):
        return [item for item in classes if isinstance(item, dict)]
    if isinstance(classes, dict):
        return [classes]
    return []


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def collect_field_values(obj, field_name):
    """Recursively collect values for field conditions with a matching name."""
    found = []
    if isinstance(obj, dict):
        field = obj.get('field')
        if isinstance(field, dict) and field.get('name') == field_name and 'value' in field:
            found.append(str(field.get('value')))
        for value in obj.values():
            found.extend(collect_field_values(value, field_name))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(collect_field_values(item, field_name))
    return found


def contains_field_name(obj, field_name):
    if isinstance(obj, dict):
        field = obj.get('field')
        if isinstance(field, dict) and field.get('name') == field_name:
            return True
        return any(contains_field_name(value, field_name) for value in obj.values())
    if isinstance(obj, list):
        return any(contains_field_name(item, field_name) for item in obj)
    return False




def contains_not_field_value(obj, field_name, field_value):
    """Return True if obj contains {"not": {"field": {name, value}}}."""
    if isinstance(obj, dict):
        not_obj = obj.get('not')
        if isinstance(not_obj, dict):
            values = collect_field_values(not_obj, field_name)
            if str(field_value) in values:
                return True
        return any(contains_not_field_value(value, field_name, field_value) for value in obj.values())
    if isinstance(obj, list):
        return any(contains_not_field_value(item, field_name, field_value) for item in obj)
    return False

def contains_query_digest_replacement(obj):
    """Return True if a print rule replaces text with query_digest."""
    if isinstance(obj, dict):
        function = obj.get('function')
        if isinstance(function, dict) and function.get('name') == 'query_digest':
            return True
        return any(contains_query_digest_replacement(value) for value in obj.values())
    if isinstance(obj, list):
        return any(contains_query_digest_replacement(item) for item in obj)
    return False


def unique_text(values):
    result = []
    for value in values:
        text = str(value)
        if text and text not in result:
            result.append(text)
    return result


def describe_connection_class(class_item):
    events = []
    details = []
    for event in as_list(class_item.get('event')):
        if isinstance(event, dict):
            for event_name in as_list(event.get('name')):
                if event_name:
                    events.append(str(event_name))
            log = event.get('log')
            if collect_field_values(log, 'connection_type'):
                details.append('non-SSL TCP connection_type=' + ','.join(unique_text(collect_field_values(log, 'connection_type'))))
            if contains_field_name(log, 'status'):
                status_values = unique_text(collect_field_values(log, 'status'))
                if contains_not_field_value(log, 'status', 0):
                    details.append('failed connects')
                elif status_values == ['0']:
                    details.append('successful connects')
                elif status_values:
                    details.append('status=' + ','.join(status_values))
                else:
                    details.append('status condition')
    if not events and class_item.get('log') is True:
        details.append('all connection-class events')
    if events:
        details.insert(0, 'events=' + ','.join(unique_text(events)))
    return 'connection: ' + ('; '.join(details) if details else 'configured')


def describe_general_class(class_item):
    event = class_item.get('event')
    events = []
    conditions = []
    for item in as_list(event):
        if not isinstance(item, dict):
            continue
        for event_name in as_list(item.get('name')):
            if event_name:
                events.append(str(event_name))
        log = item.get('log')
        commands = unique_text(collect_field_values(log, 'general_sql_command.str'))
        if commands:
            if len(commands) > 8:
                conditions.append('SQL commands=' + ','.join(commands[:8]) + ', ... +' + str(len(commands) - 8))
            else:
                conditions.append('SQL commands=' + ','.join(commands))
        if contains_field_name(log, 'general_error_code'):
            conditions.append('failed operations/general_error_code != 0')
        if contains_query_digest_replacement(item):
            conditions.append('query text replaced with query_digest')
    if not events and class_item.get('log') is True:
        conditions.append('all general events')
    prefix = 'general'
    if events:
        prefix += ': events=' + ','.join(unique_text(events))
    return prefix + ('; ' + '; '.join(conditions) if conditions else ': configured')


def describe_table_access_class(class_item):
    event = class_item.get('event', {}) if isinstance(class_item.get('event'), dict) else {}
    events = unique_text([str(item) for item in as_list(event.get('name')) if item])
    targets = []
    filter_body = event.get('filter', {})
    for table_filter in as_list(filter_body.get('activate', {}).get('or')):
        schemas = collect_field_values(table_filter, 'table_database.str')
        tables = collect_field_values(table_filter, 'table_name.str')
        if schemas and tables:
            targets.append(schemas[0] + '.' + tables[0])
    details = []
    if events:
        details.append('events=' + ','.join(events))
    if targets:
        target_text = ','.join(targets[:5])
        if len(targets) > 5:
            target_text += ', ... +' + str(len(targets) - 5)
        details.append('tables=' + target_text)
    if contains_query_digest_replacement(event):
        details.append('table query text replaced with query_digest')
    return 'table_access: ' + ('; '.join(details) if details else 'configured')


def describe_message_class(class_item):
    events = []
    for event in as_list(class_item.get('event')):
        if isinstance(event, dict):
            for event_name in as_list(event.get('name')):
                if event_name:
                    events.append(str(event_name))
    if events:
        return 'message: events=' + ','.join(unique_text(events))
    if class_item.get('log') is True:
        return 'message: all message events'
    return 'message: configured'


def describe_audit_filter_doc(filter_doc):
    """Return a high-level human description for a stored audit filter document."""
    if not isinstance(filter_doc, dict) or 'filter' not in filter_doc:
        return 'Not a recognized audit filter document'

    filter_body = filter_doc.get('filter')
    if not isinstance(filter_body, dict):
        return 'Filter body is not an object'

    descriptions = []
    if filter_body.get('log') is True and 'class' not in filter_body:
        descriptions.append('logs everything')
    elif filter_body.get('log') is False:
        descriptions.append('inclusive filter: logs only matching classes/events')

    if filter_body.get('id'):
        descriptions.append('subfilter id=' + str(filter_body.get('id')))

    for class_item in iter_audit_classes(filter_body):
        class_name = class_item.get('name')
        if class_name == 'connection':
            descriptions.append(describe_connection_class(class_item))
        elif class_name == 'general':
            descriptions.append(describe_general_class(class_item))
        elif class_name == 'table_access':
            descriptions.append(describe_table_access_class(class_item))
        elif class_name == 'message':
            descriptions.append(describe_message_class(class_item))
        else:
            descriptions.append(str(class_name or 'unknown class') + ': configured')

    if contains_query_digest_replacement(filter_doc) and not any('query_digest' in item for item in descriptions):
        descriptions.append('query text replacement uses query_digest')

    return '; '.join(descriptions) if descriptions else 'recognized audit filter with no class-specific summary'


def show_audit_filters_raw(session, shell):
    r = session.run_sql("select * from mysql.audit_log_filter")
    if shell.dump_rows(r) > 0:
        print(' ')
    else:
        print("No audit filters")


def show_audit_filters_pretty_json(session):
    filters = fetch_audit_filter_rows(session)
    if not filters:
        print("No audit filters")
        return

    for filter_row in filters:
        print("\nFilter: " + filter_row['name'])
        filter_doc, error = parse_filter_json(filter_row['filter_json'])
        if error:
            print("Invalid JSON stored for this filter: " + error)
            print(filter_row['filter_json'])
        else:
            print(json.dumps(filter_doc, indent=2, sort_keys=True))


def show_audit_filters_summary(session):
    filters = fetch_audit_filter_rows(session)
    if not filters:
        print("No audit filters")
        return

    users_by_filter = fetch_audit_filter_users_by_filter(session)
    print("\nAudit filter summary")
    for idx, filter_row in enumerate(filters, start=1):
        filter_doc, error = parse_filter_json(filter_row['filter_json'])
        if error:
            description = 'Invalid JSON: ' + error
        else:
            description = describe_audit_filter_doc(filter_doc)
        users = users_by_filter.get(filter_row['name'], [])
        if users:
            users_text = ', '.join(users)
        else:
            users_text = '- no assigned users -'
        print(str(idx) + ". " + filter_row['name'])
        print("   Users: " + users_text)
        print("   Description: " + description)


def show_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    print("Show audit filters")
    print("1 - Current as-is")
    print("2 - Pretty print JSON")
    print("3 - High level description of each filter with list of users using it")
    print("4 - Return")

    sel = check_user_input_pos_int("Selection")
    if sel == '1':
        show_audit_filters_raw(session, shell)
    elif sel == '2':
        show_audit_filters_pretty_json(session)
    elif sel == '3':
        show_audit_filters_summary(session)
    elif sel == '4':
        return
    else:
        print("Invalid selection")
    return

def name_filter(session):
    namenotok = True
    while namenotok:
        fname = read_wizard_input("Please name your filter").strip()
        if not fname:
            print("Name cannot be blank")
            continue

        name_exists = "select count(*) as num_name from mysql.audit_log_filter where name = '" + sql_string(fname) + "'"
        r = session.run_sql(name_exists)
        o = r.fetch_one()
        num_tabs = o.get_field("num_name")
        if num_tabs > 0:
            print("Name exists - please use a different name")
        elif check_user_input_yes("Is that a good name (Y/N)"):
            namenotok = False
    return fname

def check_schema_name(session):
    namenotok = True
    while namenotok:
        fname = read_wizard_input("Schema Name").strip()
        name_exists = "select count(*) as num_name from information_schema.schemata where schema_name= '" + sql_string(fname) + "'"
        r = session.run_sql(name_exists)
        o = r.fetch_one()
        num_tabs = o.get_field("num_name")
        if num_tabs > 0:
            namenotok = False
        else:
            print("No database/schema of that name exists - please try again")
    return fname

def check_schema_for_table_name(session, schem):
    namenotok = True
    while namenotok:
        fname = read_wizard_input("Table Name").strip()
        name_exists = (
            "select count(*) as num_name from information_schema.tables "
            "where table_schema='" + sql_string(schem) + "' and table_name='" + sql_string(fname) + "'"
        )
        r = session.run_sql(name_exists)
        o = r.fetch_one()
        num_tabs = o.get_field("num_name")
        if num_tabs > 0:
            namenotok = False
        else:
            print("No table in the selected database/schema of that name exists - please try again")
    return fname

def build_log_everything_filter():
    return {"filter": {"log": True}}


def build_filter_from_classes(class_items, needs_ref_id=False):
    """Build one inclusive audit filter from selected class entries."""
    if not class_items:
        return None

    filter_body = {
        "log": False,
        "class": class_items[0] if len(class_items) == 1 else class_items
    }
    if needs_ref_id:
        filter_body["id"] = "main"
    return {"filter": filter_body}


def check_user_input_choice_set(prompt, valid_choices):
    """Read one or more numeric menu choices, separated by commas or spaces."""
    valid_choices = set(valid_choices)
    while True:
        raw = read_wizard_input(prompt).strip()
        tokens = [tok.strip() for tok in raw.replace(',', ' ').split() if tok.strip()]
        if not tokens:
            print("Please enter at least one selection.")
            continue
        bad = [tok for tok in tokens if tok not in valid_choices]
        if bad:
            print("Invalid selection(s): " + ', '.join(bad))
            print("Valid choices are: " + ', '.join(sorted(valid_choices, key=lambda x: int(x))))
            continue
        return set(tokens)


def build_connection_class_from_choice():
    print("Creating Connection Audit Logging Filter")
    print("Do you want to Log")
    print("1: All connection-class events")
    print("2: Only Failed Connect Events")
    print("3: Only Successful Connect Events")
    print("4: Connect and Disconnect Events")
    print("5: change_user re-authentication events")
    print("6: Connect, change_user, and Disconnect Events")

    while True:
        pick = check_user_input_pos_int("Enter 1, 2, 3, 4, 5, or 6: ")
        if pick == '1':
            print("Audit all connection-class events")
            return {"name": "connection", "log": True}
        if pick == '2':
            print("Audit failed connect events")
            return {
                "name": "connection",
                "event": {
                    "name": "connect",
                    "log": {"not": {"field": {"name": "status", "value": 0}}}
                }
            }
        if pick == '3':
            print("Audit successful connect events")
            return {
                "name": "connection",
                "event": {
                    "name": "connect",
                    "log": {"field": {"name": "status", "value": 0}}
                }
            }
        if pick == '4':
            print("Audit connect and disconnect events")
            return {
                "name": "connection",
                "event": [
                    {"name": "connect", "log": True},
                    {"name": "disconnect", "log": True}
                ]
            }
        if pick == '5':
            print("Audit change_user re-authentication events")
            return {
                "name": "connection",
                "event": {
                    "name": "change_user",
                    "log": True
                }
            }
        if pick == '6':
            print("Audit connect, change_user, and disconnect events")
            return {
                "name": "connection",
                "event": [
                    {"name": "connect", "log": True},
                    {"name": "change_user", "log": True},
                    {"name": "disconnect", "log": True}
                ]
            }
        print("Please enter 1, 2, 3, 4, 5, or 6")



def access_failure_condition():
    return {"not": {"field": {"name": "general_error_code", "value": 0}}}


def build_access_failures_class():
    print("Adding general status failures to the combined filter")
    return {
        "name": "general",
        "event": {
            "name": "status",
            "log": access_failure_condition()
        }
    }


DDL_COMMANDS = [
    ("alter_dbs", "alter_db"),
    ("alter_db_upgrades", "alter_db_upgrade"),
    ("alter_events", "alter_event"),
    ("alter_functions", "alter_function"),
    ("alter_instances", "alter_instance"),
    ("alter_procedures", "alter_procedure"),
    ("alter_servers", "alter_server"),
    ("alter_tables", "alter_table"),
    ("alter_tablespaces", "alter_tablespace"),
    ("create_dbs", "create_db"),
    ("create_events", "create_event"),
    ("create_functions", "create_function"),
    ("create_indexes", "create_index"),
    ("create_procedures", "create_procedure"),
    ("create_servers", "create_server"),
    ("create_tables", "create_table"),
    ("create_triggers", "create_trigger"),
    ("create_udfs", "create_udf"),
    ("create_views", "create_view"),
    ("drop_dbs", "drop_db"),
    ("drop_events", "drop_event"),
    ("drop_functions", "drop_function"),
    ("drop_indexes", "drop_index"),
    ("drop_procedures", "drop_procedure"),
    ("drop_servers", "drop_server"),
    ("drop_tables", "drop_table"),
    ("drop_triggers", "drop_trigger"),
    ("drop_views", "drop_view"),
    ("rename_tables", "rename_table"),
]


def build_ddl_condition(selected_commands):
    return {
        "and": [
            {
                "or": [
                    {"field": {"name": "general_command.str", "value": "Query"}},
                    {"field": {"name": "general_command.str", "value": "Execute"}}
                ]
            },
            {
                "or": [
                    {"field": {"name": "general_sql_command.str", "value": command}}
                    for command in selected_commands
                ]
            }
        ]
    }


def query_or_execute_condition():
    return {
        "or": [
            {"field": {"name": "general_command.str", "value": "Query"}},
            {"field": {"name": "general_command.str", "value": "Execute"}}
        ]
    }


def query_digest_print(field_name):
    """Return a print rule that replaces statement text with query_digest."""
    return {
        "field": {
            "name": field_name,
            "print": False,
            "replace": {
                "function": {
                    "name": "query_digest"
                }
            }
        }
    }


def build_sql_command_condition(selected_commands):
    """Build a general/status log condition for SQL command names."""
    commands = []
    for command in selected_commands:
        if command and command not in commands:
            commands.append(command)

    if not commands:
        return None

    command_conditions = [
        {"field": {"name": "general_sql_command.str", "value": command}}
        for command in commands
    ]
    if len(command_conditions) == 1:
        command_condition = command_conditions[0]
    else:
        command_condition = {"or": command_conditions}

    return {
        "and": [
            query_or_execute_condition(),
            command_condition
        ]
    }


def build_general_sql_commands_class(selected_commands, mask_query=False):
    """Build a general/status class for one or more general_sql_command values."""
    log_condition = build_sql_command_condition(selected_commands)
    if log_condition is None:
        return None

    event = {
        "name": "status",
        "log": log_condition
    }
    if mask_query:
        event["print"] = query_digest_print("general_query.str")

    return {
        "name": "general",
        "event": event
    }


def fetch_sql_statement_commands(session):
    """Return statement/sql command names available in this MySQL version."""
    try:
        stmt = (
            "SELECT SUBSTRING(NAME, LENGTH('statement/sql/') + 1) AS command_name "
            "FROM performance_schema.setup_instruments "
            "WHERE NAME LIKE 'statement/sql/%' "
            "ORDER BY NAME"
        )
        rows = session.run_sql(stmt).fetch_all()
        return [str(row[0]) for row in rows]
    except Exception as e:
        print("Unable to read performance_schema.setup_instruments: " + str(e))
        return []


def unique_in_order(values):
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def commands_available_or_candidates(session, label, candidates, contains_any=None):
    """Use discovered statement/sql commands when possible; otherwise use candidates."""
    available = fetch_sql_statement_commands(session)
    contains_any = contains_any or []
    if available:
        available_set = set(available)
        selected = [command for command in candidates if command in available_set]
        for command in available:
            if any(token in command for token in contains_any) and command not in selected:
                selected.append(command)
        if selected:
            print(label + " command values:")
            print("  " + ", ".join(selected))
            return selected
        print("No exact command matches discovered for " + label + "; using built-in candidates.")
    else:
        print("Using built-in command candidates for " + label + ".")
    print("  " + ", ".join(candidates))
    return unique_in_order(candidates)


USER_ROLE_PRIVILEGE_COMMANDS = [
    "alter_user",
    "alter_user_default_role",
    "create_role",
    "create_user",
    "drop_role",
    "drop_user",
    "grant",
    "grant_roles",
    "revoke",
    "revoke_roles",
]

AUDIT_ADMIN_COMMANDS = [
    "install_component",
    "uninstall_component",
    "install_plugin",
    "uninstall_plugin",
    "set_option",
    "set_resource_group",
    "set_password",
    "flush",
]

ADMIN_SERVER_COMMANDS = [
    "admin_commands",
    "flush",
    "kill",
    "reset",
    "reset_persist",
    "restart_server",
    "shutdown",
    "set_option",
    "set_resource_group",
    "install_component",
    "uninstall_component",
    "install_plugin",
    "uninstall_plugin",
]

STORED_CODE_COMMANDS = [
    "create_procedure",
    "alter_procedure",
    "drop_procedure",
    "create_function",
    "alter_function",
    "drop_function",
    "create_trigger",
    "drop_trigger",
    "create_event",
    "alter_event",
    "drop_event",
]

BULK_DATA_MOVEMENT_COMMANDS = [
    "load",
    "load_table",
    "load_xml",
    "import",
    "export",
]

REPLICATION_TOPOLOGY_COMMANDS = [
    "change_master",
    "change_replication_source",
    "start_slave",
    "stop_slave",
    "start_replica",
    "stop_replica",
    "reset_slave",
    "reset_replica",
    "show_replicas",
    "show_replica_status",
    "group_replication_start",
    "group_replication_stop",
    "clone",
]


def build_user_role_privilege_class(session):
    print("Adding user, role, and privilege changes")
    commands = commands_available_or_candidates(
        session,
        "User/role/privilege",
        USER_ROLE_PRIVILEGE_COMMANDS,
        contains_any=["user", "role", "grant", "revoke"]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_audit_admin_class(session):
    print("Adding audit administration changes")
    print("Note: audit_log_filter_* function calls may appear as SELECT statements; this preset captures component/plugin installs and SET-style administration commands.")
    commands = commands_available_or_candidates(
        session,
        "Audit administration",
        AUDIT_ADMIN_COMMANDS,
        contains_any=["install", "uninstall", "set_option", "flush"]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_admin_server_class(session):
    print("Adding administrative server commands")
    commands = commands_available_or_candidates(
        session,
        "Administrative server",
        ADMIN_SERVER_COMMANDS,
        contains_any=[]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_stored_code_class(session):
    print("Adding stored program and scheduled event changes")
    commands = commands_available_or_candidates(
        session,
        "Stored code / scheduled event",
        STORED_CODE_COMMANDS,
        contains_any=["procedure", "function", "trigger", "event"]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_bulk_data_movement_class(session):
    print("Adding bulk import/export and data movement commands")
    commands = commands_available_or_candidates(
        session,
        "Bulk data movement",
        BULK_DATA_MOVEMENT_COMMANDS,
        contains_any=["load", "import", "export"]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_replication_topology_class(session):
    print("Adding replication and topology administration commands")
    commands = commands_available_or_candidates(
        session,
        "Replication/topology",
        REPLICATION_TOPOLOGY_COMMANDS,
        contains_any=["replica", "replication", "source", "master", "slave", "group_replication", "clone"]
    )
    return build_general_sql_commands_class(commands, mask_query=True)


def build_non_ssl_connection_class():
    print("Adding non-SSL TCP connection attempts")
    return {
        "name": "connection",
        "event": {
            "name": "connect",
            "log": {
                "field": {
                    "name": "connection_type",
                    "value": "::tcp/ip"
                }
            }
        }
    }


def build_message_class():
    print("Adding application audit messages")
    print("This captures audit message events emitted by the audit message component/UDF when available.")
    return {
        "name": "message",
        "event": [
            {"name": "user", "log": True},
            {"name": "internal", "log": True}
        ]
    }


def build_custom_sql_command_class(session):
    print("Creating custom SQL command group from performance_schema.setup_instruments")
    available = fetch_sql_statement_commands(session)
    if available:
        term = read_wizard_input("Optional search text to narrow the command list, or press Enter for all").strip().lower()
        shown = [cmd for cmd in available if not term or term in cmd.lower()]
        if not shown:
            print("No commands matched that search text; showing all commands.")
            shown = available

        for idx, command in enumerate(shown, start=1):
            print(str(idx) + " - " + command)
        valid = {str(i) for i in range(1, len(shown) + 1)}
        choices = check_user_input_choice_set("Command selection(s)", valid)
        selected = [shown[int(choice) - 1] for choice in sorted(choices, key=lambda x: int(x))]
    else:
        raw = read_wizard_input("Enter general_sql_command.str values separated by commas").strip()
        selected = unique_in_order([item.strip() for item in raw.split(',') if item.strip()])

    if not selected:
        print("No SQL command values selected; skipping custom command group.")
        return None

    mask = check_user_input_yes("Replace logged SQL statement text with query_digest? Y/N")
    return build_general_sql_commands_class(selected, mask_query=mask)


def select_ddl_commands():
    print("Please select the DDL event types you wish to capture")
    selected_commands = []
    for label, command in DDL_COMMANDS:
        if check_user_input_yes(label + "? - Y/N"):
            selected_commands.append(command)
    return selected_commands


def build_ddl_class():
    selected_commands = select_ddl_commands()
    if not selected_commands:
        print("No DDL commands selected; skipping DDL in this filter.")
        return None

    return {
        "name": "general",
        "event": {
            "name": "status",
            "log": build_ddl_condition(selected_commands)
        }
    }


def merge_general_classes(general_classes):
    """Merge several general/status log conditions into one general class."""
    conditions = []
    mask_query = False
    for class_item in general_classes:
        event = class_item.get("event", {})
        if class_item.get("name") == "general" and event.get("name") == "status" and "log" in event:
            conditions.append(event["log"])
            if "print" in event:
                mask_query = True

    if not conditions:
        return None

    event = {
        "name": "status",
        "log": conditions[0] if len(conditions) == 1 else {"or": conditions}
    }
    if mask_query:
        event["print"] = query_digest_print("general_query.str")

    return {
        "name": "general",
        "event": event
    }


def build_table_dml_class(session):
    print("Creating Audit Log for Tables and DML types")
    print("Please select 1-4 table event types you wish to capture")

    events = []
    if check_user_input_yes("INSERTs / LOAD DATA / LOAD XML? Y/N"):
        events.append("insert")
    if check_user_input_yes("UPDATEs? Y/N"):
        events.append("update")
    if check_user_input_yes("DELETEs / TRUNCATE TABLE? Y/N"):
        events.append("delete")
    if check_user_input_yes("READs / SELECTs? Y/N"):
        events.append("read")

    if not events:
        print("No table event types selected; skipping table access in this filter.")
        return None

    mask_table_query = check_user_input_yes("Replace logged table SQL text with query_digest? Y/N")

    print("Provide schema and table name for targeted auditing")
    table_conditions = []
    moretables = True
    while moretables:
        schname = check_schema_name(session)
        tblname = check_schema_for_table_name(session, schname)
        table_conditions.append({
            "and": [
                {"field": {"name": "table_database.str", "value": schname}},
                {"field": {"name": "table_name.str", "value": tblname}}
            ]
        })
        moretables = check_user_input_yes("Any additional tables? Y/N")

    event = {
        "name": events,
        "log": False,
        "filter": {
            "activate": {"or": table_conditions},
            "class": {
                "name": "general",
                "event": {
                    "name": "status",
                    "log": True,
                    "filter": {"ref": "main"}
                }
            }
        }
    }
    if mask_table_query:
        event["print"] = query_digest_print("query.str")

    return {
        "name": "table_access",
        "event": event
    }


def filter_log_everything(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    print("Creating Audit Log Everything Filter")
    filt_name = name_filter(session)
    install_audit_filter(session, shell, filt_name, build_log_everything_filter())
    return


def wb_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    filt_name = name_filter(session)
    filter_doc = build_filter_from_classes([build_workbench_connection_class()])
    install_audit_filter(session, shell, filt_name, filter_doc)
    return


def filter_log_connections_only(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    class_item = build_connection_class_from_choice()
    filt_name = name_filter(session)
    filter_doc = build_filter_from_classes([class_item])
    install_audit_filter(session, shell, filt_name, filter_doc)
    return


def filter_by_table_dml_type(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    class_item = build_table_dml_class(session)
    if class_item is None:
        return

    filter_doc = build_filter_from_classes([class_item], needs_ref_id=True)
    print(json.dumps(filter_doc, indent=2))
    filt_name = name_filter(session)
    install_audit_filter(session, shell, filt_name, filter_doc)
    return


def filter_by_ddl_type(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    print("Creating Audit Log for - Specific DDL Actions - Filter")
    class_item = build_ddl_class()
    if class_item is None:
        return

    filter_doc = build_filter_from_classes([class_item])
    print(json.dumps(filter_doc, indent=2))
    filt_name = name_filter(session)
    install_audit_filter(session, shell, filt_name, filter_doc)
    return


def filter_access_failures(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return

    print("Creating Audit Log for - Any unsuccessful accesses to objects - Filter")
    filt_name = name_filter(session)
    filter_doc = build_filter_from_classes([build_access_failures_class()])
    install_audit_filter(session, shell, filt_name, filter_doc)
    return


def new_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    rep = True
    while rep:
        print("What types actions do you wish to collect in the audit log?")
        print("Enter one or more selections separated by commas, for example: 2,4,7,8")
        print("1  - Log Everything")
        print("2  - Connections")
        print("3  - Non-SSL TCP connection attempts")
        print("4  - Failed operations")
        print("5  - Sensitive table access / table DML")
        print("6  - DDL changes")
        print("7  - User, role, and privilege changes")
        print("8  - Audit administration changes")
        print("9  - Administrative server commands")
        print("10 - Stored code / scheduled event changes")
        print("11 - Bulk import/export and data movement")
        print("12 - Replication / topology changes")
        print("13 - Custom command group from performance_schema.setup_instruments")
        print("14 - Application audit messages")
        print("15 - Return")

        selections = check_user_input_choice_set("Selection(s)", {str(i) for i in range(1, 16)})

        if '15' in selections:
            if len(selections) > 1:
                print("Return cannot be combined with filter choices.")
                continue
            rep = False
            continue

        if '1' in selections:
            if len(selections) > 1:
                print("Log Everything stands on its own. Select only 1, or choose specific event types such as 2,4,7,8.")
                continue
            filter_log_everything(session)
            continue

        class_items = []
        general_classes = []
        needs_ref_id = False

        if '2' in selections:
            class_items.append(build_connection_class_from_choice())

        if '3' in selections:
            class_items.append(build_non_ssl_connection_class())

        if '4' in selections:
            general_classes.append(build_access_failures_class())

        if '5' in selections:
            table_class = build_table_dml_class(session)
            if table_class is not None:
                class_items.append(table_class)
                needs_ref_id = True

        if '6' in selections:
            ddl_class = build_ddl_class()
            if ddl_class is not None:
                general_classes.append(ddl_class)

        if '7' in selections:
            class_item = build_user_role_privilege_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '8' in selections:
            class_item = build_audit_admin_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '9' in selections:
            class_item = build_admin_server_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '10' in selections:
            class_item = build_stored_code_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '11' in selections:
            class_item = build_bulk_data_movement_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '12' in selections:
            class_item = build_replication_topology_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '13' in selections:
            class_item = build_custom_sql_command_class(session)
            if class_item is not None:
                general_classes.append(class_item)

        if '14' in selections:
            class_items.append(build_message_class())

        general_class = merge_general_classes(general_classes)
        if general_class is not None:
            class_items.append(general_class)

        if not class_items:
            print("No implemented filter types were selected; no filter was created.")
            continue

        filter_doc = build_filter_from_classes(class_items, needs_ref_id=needs_ref_id)
        print(json.dumps(filter_doc, indent=2))
        filt_name = name_filter(session)
        install_audit_filter(session, shell, filt_name, filter_doc)

    print("Done")
    return

def del_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    r = session.run_sql("with "
        " cte1 as (select filtername, count(filtername) as fcnt from mysql.audit_log_user group by filtername),"
        " cte2 as (SELECT `audit_log_filter`.`NAME`, "
        "`audit_log_filter`.`FILTER` as f FROM `mysql`.`audit_log_filter`) "
        " SELECT distinct cte2.name as fname, ifnull(cte1.fcnt, 0) as ucnt FROM cte1 RIGHT OUTER JOIN cte2 ON cte1.filtername = cte2.name")

    n = r.fetch_one()
    dellist = []
    cantdellist = []
    while n is not None:
        if n.get_field("ucnt") > 0:
            cantdellist.append(n.get_field("fname") + " 		- has " + str(n.get_field("ucnt")) + " user(s) assigned - unable to remove")
        else:
            dellist.append(n.get_field("fname"))
        n = r.fetch_one()

    if not dellist and not cantdellist:
        print("No filters in place")
        return

    print("------------------------------------------------------------------------")
    print("These filters have users please remove the users if you wish to delete.")
    for filt in cantdellist:
        print(filt)
    print("")
    print("------------------------")
    print("Select filters to remove")
    for filt in dellist:
        rmfilt = " Do you wish to remove AUDIT FILTER - " + filt + " ? (Y/N)"
        if check_user_input_yes(rmfilt):
            remove_audit_filter(session, shell, filt)
            print("******")
    return

def del_one_user_audit_filters(userhost, session=None):
    session = fetch_session(session)
    if session is None:
        return
    print("")

    delstr = "SELECT audit_log_filter_remove_user('" + sql_string(userhost) + "')"
    session.run_sql(delstr)

    if userhost == '%':
        uname, hname = '%', ''
    else:
        split_string = userhost.split("@", 1)
        if len(split_string) != 2:
            print("Error - unable to split user@host value")
            return
        uname, hname = split_string[0], split_string[1]

    if exist_user_audit_filters(uname, hname, session):
        print("Error - User/Filter was not removed")
    else:
        print("OK - User/Filter was removed")
    return

def del_user_audit_filters(session=None):
    session = fetch_session(session)
    if session is None:
        return
    print("")

    rows = session.run_sql("select user, host, filtername from mysql.audit_log_user").fetch_all()
    if not rows:
        print("No users assigned to filters")
        return

    print("")
    print("------------------------")
    print("Select user/hosts to remove")

    deluserhostlist = []
    for n in rows:
        u = n[0]
        h = n[1]
        fn = n[2]
        userhost = audit_account_function_arg(u, h)
        display_name = audit_account_display(u, h)
        rmfilt = "Do you wish to remove the User AUDIT FILTER - User: " + display_name + " Filter: " + fn + " ? (Y/N)"
        if check_user_input_yes(rmfilt):
            deluserhostlist.append(userhost)

    for rmuserhost in deluserhostlist:
        del_one_user_audit_filters(rmuserhost, session)
    return


# Privilege classification helpers used by the audit-filter user assignment flow.
# These are intentionally heuristic: they summarize direct grants from the MySQL
# grant tables so the wizard can help a human pick the right accounts to audit.
SYSTEM_ACCOUNT_NAMES = set([
    'mysql.infoschema',
    'mysql.session',
    'mysql.sys',
    'mysqlxsys',
])

HIGH_RISK_DYNAMIC_PRIVS = set([
    'AUDIT_ADMIN',
    'BACKUP_ADMIN',
    'BINLOG_ADMIN',
    'CLONE_ADMIN',
    'CONNECTION_ADMIN',
    'ENCRYPTION_KEY_ADMIN',
    'FIREWALL_ADMIN',
    'FLUSH_ADMIN',
    'GROUP_REPLICATION_ADMIN',
    'INNODB_REDO_LOG_ARCHIVE',
    'PASSWORDLESS_USER_ADMIN',
    'PERSIST_RO_VARIABLES_ADMIN',
    'REPLICATION_APPLIER',
    'REPLICATION_SLAVE_ADMIN',
    'RESOURCE_GROUP_ADMIN',
    'ROLE_ADMIN',
    'SENSITIVE_VARIABLES_OBSERVER',
    'SERVICE_CONNECTION_ADMIN',
    'SESSION_VARIABLES_ADMIN',
    'SET_USER_ID',
    'SHOW_ROUTINE',
    'SYSTEM_USER',
    'SYSTEM_VARIABLES_ADMIN',
    'TABLE_ENCRYPTION_ADMIN',
    'TELEMETRY_LOG_ADMIN',
    'VERSION_TOKEN_ADMIN',
])

SECURITY_DYNAMIC_PRIVS = set([
    'AUDIT_ADMIN',
    'FIREWALL_ADMIN',
    'PASSWORDLESS_USER_ADMIN',
    'ROLE_ADMIN',
    'SYSTEM_USER',
])

HIGH_RISK_STATIC_PRIVS = set([
    'SUPER',
    'RELOAD',
    'SHUTDOWN',
    'PROCESS',
    'FILE',
    'CREATE USER',
    'CREATE ROLE',
    'DROP ROLE',
    'GRANT OPTION',
    'REPLICATION SLAVE',
    'REPLICATION CLIENT',
    'CREATE TABLESPACE',
])

SECURITY_STATIC_PRIVS = set([
    'CREATE USER',
    'CREATE ROLE',
    'DROP ROLE',
    'GRANT OPTION',
])

DATA_STATIC_PRIVS = set([
    'SELECT',
    'INSERT',
    'UPDATE',
    'DELETE',
    'CREATE',
    'DROP',
    'ALTER',
    'INDEX',
    'REFERENCES',
    'CREATE VIEW',
    'SHOW VIEW',
    'TRIGGER',
    'CREATE ROUTINE',
    'ALTER ROUTINE',
    'EXECUTE',
    'EVENT',
])


def row_field(row, field_name, default=None):
    """Read a named field from a MySQL Shell Row object or mapping test double."""
    try:
        return row.get_field(field_name)
    except Exception:
        pass
    try:
        return row[field_name]
    except Exception:
        return default


def row_value(row, field_name, index=None, default=None):
    """Read a named field, falling back to a positional index when needed."""
    value = row_field(row, field_name, None)
    if value is not None:
        return value
    if index is not None:
        try:
            return row[index]
        except Exception:
            pass
    return default


def run_sql_fetch_all(session, stmt):
    """Run a read-only metadata query and return rows, or [] if unsupported."""
    try:
        return session.run_sql(stmt).fetch_all()
    except Exception as exc:
        print("Warning: unable to read privilege metadata: " + str(exc))
        return []


def table_exists(session, schema_name, table_name):
    stmt = (
        "select count(*) as cnt from information_schema.tables "
        "where table_schema='" + sql_string(schema_name) + "' "
        "and table_name='" + sql_string(table_name) + "'"
    )
    try:
        row = session.run_sql(stmt).fetch_one()
        return row is not None and int(row_field(row, 'cnt', 0)) > 0
    except Exception:
        return False


def get_table_columns(session, schema_name, table_name):
    stmt = (
        "select column_name from information_schema.columns "
        "where table_schema='" + sql_string(schema_name) + "' "
        "and table_name='" + sql_string(table_name) + "' "
        "order by ordinal_position"
    )
    rows = run_sql_fetch_all(session, stmt)
    return [str(row_value(row, 'column_name', 0, '')) for row in rows]


def user_privilege_label(column_name):
    label = str(column_name)
    if label.lower().endswith('_priv'):
        label = label[:-5]
    label = label.replace('_', ' ').upper()
    if label == 'GRANT':
        label = 'GRANT OPTION'
    return label


def fetch_static_privilege_columns(session):
    columns = get_table_columns(session, 'mysql', 'user')
    return [col for col in columns if col.lower().endswith('_priv')]


def fetch_dynamic_privileges_by_account(session):
    result = {}
    if not table_exists(session, 'mysql', 'global_grants'):
        return result

    stmt = (
        "select `USER` as user_name, `HOST` as host_name, `PRIV` as priv, "
        "`WITH_GRANT_OPTION` as with_grant_option from mysql.global_grants"
    )
    for row in run_sql_fetch_all(session, stmt):
        key = (str(row_field(row, 'user_name', '')), str(row_field(row, 'host_name', '')))
        priv = str(row_field(row, 'priv', '')).upper()
        with_grant = str(row_field(row, 'with_grant_option', 'N')).upper() in ('Y', '1')
        if key not in result:
            result[key] = []
        if priv:
            result[key].append((priv, with_grant))
    return result


def fetch_count_by_account(session, table_name, user_column='User', host_column='Host'):
    result = {}
    if not table_exists(session, 'mysql', table_name):
        return result

    stmt = (
        "select `" + user_column + "` as user_name, `" + host_column + "` as host_name, "
        "count(*) as item_count from mysql.`" + table_name + "` "
        "group by `" + user_column + "`, `" + host_column + "`"
    )
    for row in run_sql_fetch_all(session, stmt):
        key = (str(row_field(row, 'user_name', '')), str(row_field(row, 'host_name', '')))
        result[key] = int(row_field(row, 'item_count', 0))
    return result


def fetch_role_edges_by_account(session):
    result = {}
    if not table_exists(session, 'mysql', 'role_edges'):
        return result

    stmt = (
        "select `FROM_USER` as user_name, `FROM_HOST` as host_name, "
        "`TO_USER` as role_user, `TO_HOST` as role_host, `WITH_ADMIN_OPTION` as admin_option "
        "from mysql.role_edges order by `FROM_USER`, `FROM_HOST`, `TO_USER`, `TO_HOST`"
    )
    for row in run_sql_fetch_all(session, stmt):
        key = (str(row_field(row, 'user_name', '')), str(row_field(row, 'host_name', '')))
        role = str(row_field(row, 'role_user', '')) + '@' + str(row_field(row, 'role_host', ''))
        admin_option = str(row_field(row, 'admin_option', 'N')).upper() in ('Y', '1')
        result.setdefault(key, []).append((role, admin_option))
    return result


def fetch_default_roles_by_account(session):
    result = {}
    if not table_exists(session, 'mysql', 'default_roles'):
        return result

    stmt = (
        "select `USER` as user_name, `HOST` as host_name, "
        "`DEFAULT_ROLE_USER` as role_user, `DEFAULT_ROLE_HOST` as role_host "
        "from mysql.default_roles order by `USER`, `HOST`, `DEFAULT_ROLE_USER`, `DEFAULT_ROLE_HOST`"
    )
    for row in run_sql_fetch_all(session, stmt):
        key = (str(row_field(row, 'user_name', '')), str(row_field(row, 'host_name', '')))
        role = str(row_field(row, 'role_user', '')) + '@' + str(row_field(row, 'role_host', ''))
        result.setdefault(key, []).append(role)
    return result


def fetch_audit_filters_by_account(session):
    result = {}
    if not table_exists(session, 'mysql', 'audit_log_user'):
        return result

    stmt = "select user, host, filtername from mysql.audit_log_user order by user, host, filtername"
    for row in run_sql_fetch_all(session, stmt):
        user_name = row_value(row, 'user', 0, '')
        host_name = row_value(row, 'host', 1, '')
        key = normalize_audit_account_key(user_name, host_name)
        result.setdefault(key, []).append(str(row_value(row, 'filtername', 2, '')))
    return result


def fetch_audit_filters_for_account(session, username, hostname):
    """Return the audit filter currently assigned to a user@host or %.

    MySQL audit filtering allows only one filter assignment per account, but
    this returns a list so the caller remains robust if unexpected metadata is
    present. The default fallback account is represented by the single account
    name %, not by a mysql.user row.
    """
    if not table_exists(session, 'mysql', 'audit_log_user'):
        return []

    if is_default_audit_account(username, hostname):
        stmt = (
            "select filtername from mysql.audit_log_user "
            "where user='%' and host='' "
            "order by filtername"
        )
    else:
        stmt = (
            "select filtername from mysql.audit_log_user "
            "where user='" + sql_string(username) + "' and host='" + sql_string(hostname) + "' "
            "order by filtername"
        )
    return [str(row_value(row, 'filtername', 0, '')) for row in run_sql_fetch_all(session, stmt)]


def classify_account_rights(account):
    user_name = account['user']
    static_privs = set(account.get('static_privs', []))
    dynamic_privs = set([priv for priv, _ in account.get('dynamic_privs', [])])
    dynamic_grant_privs = set([priv for priv, with_grant in account.get('dynamic_privs', []) if with_grant])
    db_count = account.get('db_priv_count', 0)
    table_count = account.get('table_priv_count', 0)
    column_count = account.get('column_priv_count', 0)
    routine_count = account.get('routine_priv_count', 0)
    roles = account.get('roles', [])
    default_roles = account.get('default_roles', [])

    reasons = []
    category = 'Login only / low direct grants'

    if user_name in SYSTEM_ACCOUNT_NAMES or user_name.startswith('mysql.'):
        category = 'System/internal account'
        reasons.append('built-in mysql.* account')
    elif static_privs.intersection(HIGH_RISK_STATIC_PRIVS) or dynamic_privs.intersection(HIGH_RISK_DYNAMIC_PRIVS):
        category = 'Admin / high privilege'
        high = sorted(static_privs.intersection(HIGH_RISK_STATIC_PRIVS))
        high.extend(sorted(dynamic_privs.intersection(HIGH_RISK_DYNAMIC_PRIVS)))
        reasons.append('admin=' + ','.join(high[:4]))
    elif static_privs.intersection(SECURITY_STATIC_PRIVS) or dynamic_privs.intersection(SECURITY_DYNAMIC_PRIVS):
        category = 'Security administration'
        security = sorted(static_privs.intersection(SECURITY_STATIC_PRIVS))
        security.extend(sorted(dynamic_privs.intersection(SECURITY_DYNAMIC_PRIVS)))
        reasons.append('security=' + ','.join(security[:4]))
    elif static_privs or dynamic_privs:
        category = 'Global privileged'
        if static_privs:
            reasons.append('static_global=' + str(len(static_privs)))
        if dynamic_privs:
            reasons.append('dynamic=' + str(len(dynamic_privs)))
    elif db_count or table_count or column_count or routine_count:
        category = 'Schema/object privileged'
        reasons.append('db=' + str(db_count) + ',tbl=' + str(table_count) + ',col=' + str(column_count) + ',routine=' + str(routine_count))
    elif roles or default_roles:
        category = 'Role-backed account'
        reasons.append('roles=' + str(len(roles)) + ',defaults=' + str(len(default_roles)))

    if dynamic_grant_privs:
        reasons.append('dynamic_grant=' + str(len(dynamic_grant_privs)))
    if account.get('account_locked') == 'Y':
        reasons.append('locked')

    return category, '; '.join(reasons) if reasons else 'no direct privilege rows found'


def fetch_accounts_with_classification(session):
    static_columns = fetch_static_privilege_columns(session)
    all_user_columns = set(get_table_columns(session, 'mysql', 'user'))
    select_columns = ["`User` as user_name", "`Host` as host_name"]
    if 'account_locked' in set([c.lower() for c in all_user_columns]):
        # Preserve the actual column name case from the server metadata.
        account_locked_col = [c for c in all_user_columns if c.lower() == 'account_locked'][0]
        select_columns.append("`" + account_locked_col + "` as account_locked")
    for col in static_columns:
        select_columns.append("`" + col + "`")

    stmt = "select " + ', '.join(select_columns) + " from mysql.user order by User, Host"
    rows = run_sql_fetch_all(session, stmt)

    dynamic_by_account = fetch_dynamic_privileges_by_account(session)
    db_counts = fetch_count_by_account(session, 'db')
    table_counts = fetch_count_by_account(session, 'tables_priv')
    column_counts = fetch_count_by_account(session, 'columns_priv')
    routine_counts = fetch_count_by_account(session, 'procs_priv')
    roles_by_account = fetch_role_edges_by_account(session)
    default_roles_by_account = fetch_default_roles_by_account(session)
    assigned_filters = fetch_audit_filters_by_account(session)

    accounts = []
    for row in rows:
        user_name = str(row_field(row, 'user_name', ''))
        host_name = str(row_field(row, 'host_name', ''))
        key = (user_name, host_name)
        static_privs = []
        for col in static_columns:
            if str(row_field(row, col, 'N')).upper() == 'Y':
                static_privs.append(user_privilege_label(col))

        account = {
            'user': user_name,
            'host': host_name,
            'userhost': user_name + '@' + host_name,
            'account_locked': str(row_field(row, 'account_locked', 'N')).upper(),
            'static_privs': static_privs,
            'dynamic_privs': dynamic_by_account.get(key, []),
            'db_priv_count': db_counts.get(key, 0),
            'table_priv_count': table_counts.get(key, 0),
            'column_priv_count': column_counts.get(key, 0),
            'routine_priv_count': routine_counts.get(key, 0),
            'roles': roles_by_account.get(key, []),
            'default_roles': default_roles_by_account.get(key, []),
            'assigned_filters': assigned_filters.get(key, []),
        }
        account['classification'], account['classification_reason'] = classify_account_rights(account)
        accounts.append(account)

    default_key = ('%', '')
    accounts.append(default_fallback_account(assigned_filters.get(default_key, [])))
    return accounts


def shorten_text(value, width):
    value = str(value)
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[:width - 3] + '...'


def print_account_classification_table(accounts):
    if not accounts:
        print("No MySQL accounts were found in mysql.user")
        return

    print("")
    print("Available MySQL accounts and default fallback")
    print("#    User@Host                         Locked  Audit filter(s)             State          Classification              Reason")
    print("---- --------------------------------- ------- --------------------------- -------------- --------------------------- ------------------------------")
    for idx, account in enumerate(accounts, start=1):
        filters = ','.join(account.get('assigned_filters', [])) or '-'
        state = 'assigned' if account.get('assigned_filters') else 'available'
        print(
            str(idx).rjust(3) + "  " +
            shorten_text(account['userhost'], 33).ljust(33) + " " +
            account.get('account_locked', 'N').ljust(7) + " " +
            shorten_text(filters, 27).ljust(27) + " " +
            state.ljust(14) + " " +
            shorten_text(account['classification'], 27).ljust(27) + " " +
            shorten_text(account['classification_reason'], 30)
        )
    print("")
    print("Accounts marked 'assigned' already have an audit filter and cannot be selected here.")
    print("The % default fallback applies to accounts that have no explicit audit filter assignment.")
    print("Use 'Delete users from an audit filter' first if you want to move an account or the fallback to another filter.")
    print("Classification is a direct-grant summary from mysql.user, mysql.global_grants, and object-level grant tables.")
    print("Role inheritance can make effective privileges broader than the direct summary shown here.")


def fetch_audit_filters_for_selection(session):
    rows = run_sql_fetch_all(
        session,
        "select f.name as filter_name, count(u.user) as assigned_count "
        "from mysql.audit_log_filter f "
        "left join mysql.audit_log_user u on u.filtername = f.name "
        "group by f.name order by f.name"
    )
    result = []
    for row in rows:
        result.append((str(row_value(row, 'filter_name', 0, '')), int(row_field(row, 'assigned_count', 0))))
    return result


def choose_audit_filter(session):
    filters = fetch_audit_filters_for_selection(session)
    if not filters:
        print("No audit filters")
        return None

    print("")
    print("Available audit filters")
    for idx, (filter_name, assigned_count) in enumerate(filters, start=1):
        print(str(idx) + " - " + filter_name + " (assigned accounts: " + str(assigned_count) + ")")

    while True:
        pick = read_wizard_input("Enter a filter name or number from the above list").strip()
        if not pick:
            print("Please enter a filter name or number.")
            continue
        if pick.isdigit():
            idx = int(pick)
            if idx >= 1 and idx <= len(filters):
                return filters[idx - 1][0]
        for filter_name, _ in filters:
            if pick == filter_name:
                return filter_name
        print("Bad filter name/number please re-enter.")


def choose_account_for_audit_filter(session):
    accounts = fetch_accounts_with_classification(session)
    print_account_classification_table(accounts)
    if not accounts:
        return None, None

    while True:
        pick = read_wizard_input("Enter an available account number to assign, D for default fallback %, M for manual entry, or Q to cancel").strip()
        if not pick:
            print("Please enter an account number, D, M, or Q.")
            continue
        if pick.upper() == 'Q':
            return None, None
        if pick.upper() == 'D':
            existing_filters = fetch_audit_filters_for_account(session, '%', '')
            if existing_filters:
                print(
                    "% (default fallback) already has audit filter " +
                    ','.join(existing_filters) + ". Remove that assignment before adding another filter."
                )
                continue
            print("Selected % (default fallback) - applies to accounts without explicit audit filter assignment")
            return '%', ''
        if pick.upper() == 'M':
            username = read_wizard_input("Enter User Name, or % for default fallback").strip()
            if username == '%':
                hostname = ''
            else:
                hostname = read_wizard_input("Enter Hostname").strip()
            existing_filters = fetch_audit_filters_for_account(session, username, hostname)
            if existing_filters:
                print(
                    audit_account_display(username, hostname) + " already has audit filter " +
                    ','.join(existing_filters) + ". Remove that assignment before adding another filter."
                )
                continue
            return username, hostname
        if pick.isdigit():
            idx = int(pick)
            if idx >= 1 and idx <= len(accounts):
                account = accounts[idx - 1]
                existing_filters = account.get('assigned_filters', [])
                if existing_filters:
                    print(
                        account['userhost'] + " already has audit filter " +
                        ','.join(existing_filters) + ". Remove that assignment before adding another filter."
                    )
                    continue
                print("Selected " + account['userhost'] + " - " + account['classification'])
                if account['classification'] in ('Admin / high privilege', 'System/internal account'):
                    if not check_user_input_yes("This is a high-risk/system account. Assign this filter? Y/N"):
                        continue
                return account['user'], account['host']
        print("Invalid account selection.")


def assign_filter_to_user(session, username, hostname, filter_name):
    if not check_user_name(username, hostname, session):
        print("Full User Account Name is not ok")
        return

    existing_filters = fetch_audit_filters_for_account(session, username, hostname)
    userhost = audit_account_function_arg(username, hostname)
    display_name = audit_account_display(username, hostname)
    if existing_filters:
        if filter_name in existing_filters:
            print(display_name + " is already assigned to audit filter " + filter_name + ". No change made.")
        else:
            print(
                display_name + " is already assigned to audit filter " + ','.join(existing_filters) +
                ". Remove that assignment before adding " + filter_name + "."
            )
        return

    if is_default_audit_account(username, hostname):
        print('Adding filter to the default (%) global audit fallback')
    else:
        print('Full User Account Name is confirmed - Adding User to Filter')
    add_filter = "SELECT audit_log_filter_set_user('" + sql_string(userhost) + "','" + sql_string(filter_name) + "')"
    print(add_filter)
    session.run_sql(add_filter)
    confirmed_filters = fetch_audit_filters_for_account(session, username, hostname)
    if filter_name in confirmed_filters:
        print("OK - User/Filter Confirmed")
    else:
        print("Error - User/Filter not added")

def show_user_audit_filters(session=None):
    session = fetch_session(session)
    if session is None:
        return
    print("")

    assignments = fetch_audit_filters_by_account(session)
    if not assignments:
        print("No users")
        return

    accounts = fetch_accounts_with_classification(session)
    account_by_key = {(acct['user'], acct['host']): acct for acct in accounts}

    print("Assigned audit filters")
    print("User@Host                         Filter(s)                   Classification              Reason")
    print("--------------------------------- --------------------------- --------------------------- ------------------------------")
    for key in sorted(assignments.keys()):
        account = account_by_key.get(key)
        if account is None:
            classification = 'Unknown account'
            reason = 'not found in mysql.user'
            userhost = key[0] + '@' + key[1]
        else:
            classification = account['classification']
            reason = account['classification_reason']
            userhost = account['userhost']
        print(
            shorten_text(userhost, 33).ljust(33) + " " +
            shorten_text(','.join(assignments[key]), 27).ljust(27) + " " +
            shorten_text(classification, 27).ljust(27) + " " +
            shorten_text(reason, 30)
        )
    return

def exist_user_audit_filters(uname, hname, session=None):
    session = fetch_session(session)
    if session is None:
        return False

    key = normalize_audit_account_key(uname, hname)
    stmt = (
        "select count(*) as num_name from mysql.audit_log_user "
        "where USER ='" + sql_string(key[0]) + "' and HOST ='" + sql_string(key[1]) + "'"
    )
    r = session.run_sql(stmt)
    x = r.fetch_one()
    return x is not None and int(x.get_field("num_name")) > 0

def add_user_audit_filters(session=None):
    session = fetch_session(session)
    if session is None:
        return
    print("")

    pickfilter = choose_audit_filter(session)
    if pickfilter is None:
        return

    username, hostname = choose_account_for_audit_filter(session)
    if username is None or hostname is None:
        print("No account selected")
        return

    assign_filter_to_user(session, username, hostname, pickfilter)
    return

def fetch_scalar_int(session, stmt, field_name):
    """Run a SELECT statement that returns one integer field."""
    row = session.run_sql(stmt).fetch_one()
    if row is None:
        return 0
    return int(row.get_field(field_name))


def audit_plugin_installed(session):
    """Return True when the deprecated audit_log plugin is active."""
    stmt = (
        "SELECT COUNT(*) AS cnt "
        "FROM information_schema.PLUGINS "
        "WHERE PLUGIN_NAME = 'audit_log' AND PLUGIN_STATUS = 'ACTIVE'"
    )
    return fetch_scalar_int(session, stmt, 'cnt') > 0


def audit_component_installed(session):
    """Return True when the audit log component is installed.

    MySQL 9.x uses mysql.component to record installed components. Older
    releases or users without access to mysql.component may throw an error;
    treat that as not installed so plugin-based installs still work.
    """
    try:
        stmt = (
            "SELECT COUNT(*) AS cnt "
            "FROM mysql.component "
            "WHERE component_urn = 'file://component_audit_log'"
        )
        return fetch_scalar_int(session, stmt, 'cnt') > 0
    except Exception as e:
        print("Audit component check skipped: " + str(e))
        return False


def audit_filter_tables_installed(session):
    """Return True when the audit filter metadata tables exist."""
    stmt = (
        "SELECT COUNT(*) AS cnt "
        "FROM information_schema.tables "
        "WHERE table_schema = 'mysql' "
        "AND table_name IN ('audit_log_filter','audit_log_user')"
    )
    return fetch_scalar_int(session, stmt, 'cnt') == 2


def audit_loadable_functions_installed(session):
    """Best-effort function check for plugin installs.

    The audit log component internally registers its audit_log_* functions, so
    they may not appear in mysql.func. For component mode this is advisory only.
    """
    try:
        stmt = (
            "SELECT COUNT(*) AS cnt "
            "FROM mysql.func "
            "WHERE name IN ("
            "'audit_log_filter_set_filter',"
            "'audit_log_filter_remove_filter',"
            "'audit_log_filter_set_user',"
            "'audit_log_filter_remove_user',"
            "'audit_log_filter_flush')"
        )
        return fetch_scalar_int(session, stmt, 'cnt')
    except Exception as e:
        print("Audit function metadata check skipped: " + str(e))
        return 0


def fetch_global_variable(session, variable_name):
    """Return a global system variable value, or None if it is unavailable."""
    try:
        stmt = "SHOW GLOBAL VARIABLES LIKE '" + sql_string(variable_name) + "'"
        row = session.run_sql(stmt).fetch_one()
        if row is None:
            return None
        return row[1]
    except Exception as e:
        print("Audit setting check skipped for " + variable_name + ": " + str(e))
        return None


def print_setting_status(name, current_value, recommended_value, startup_only=False):
    """Print one audit setting status line and return True when already correct."""
    if current_value is None:
        print("  " + name + " : unavailable")
        return False

    current_text = str(current_value).upper()
    recommended_text = str(recommended_value).upper()
    if current_text == recommended_text:
        print("  " + name + " : " + str(current_value) + " (OK)")
        return True

    if startup_only:
        print("  " + name + " : " + str(current_value) + " -> recommend " + str(recommended_value) + " (startup setting)")
    else:
        print("  " + name + " : " + str(current_value) + " -> recommend " + str(recommended_value))
    return False


def check_audit_recommended_settings(session, plugin_ok=False, component_ok=False):
    """Report recommended audit logging settings after install validation.

    The legacy audit plugin exposes underscore-style variables. The MySQL 9.x
    audit component exposes dotted component variables and writes JSON audit log
    files by design, so there is no audit_log.format setting to check there.
    This function is advisory only; it does not change server configuration.
    """
    print("\n***** Checking recommended audit logging settings")

    if plugin_ok:
        audit_format = fetch_global_variable(session, 'audit_log_format')
        unix_ts = fetch_global_variable(session, 'audit_log_format_unix_timestamp')

        print("Audit plugin settings:")
        format_ok = print_setting_status('audit_log_format', audit_format, 'JSON', startup_only=True)
        ts_ok = print_setting_status('audit_log_format_unix_timestamp', unix_ts, 'ON')

        if not format_ok or not ts_ok:
            print("Recommended plugin configuration:")
            if not format_ok:
                print("  my.cnf/startup option: audit_log_format=JSON")
            if not ts_ok:
                print("  runtime/persistent option: SET PERSIST audit_log_format_unix_timestamp = ON;")
            print("Note: changing audit_log_format requires a restart; changing audit_log_format_unix_timestamp rotates the audit log.")

    if component_ok:
        unix_ts = fetch_global_variable(session, 'audit_log.format_unix_timestamp')

        print("Audit component settings:")
        print("  audit log format : JSON (component format)")
        ts_ok = print_setting_status('audit_log.format_unix_timestamp', unix_ts, 'ON')
        if not ts_ok:
            print("Recommended component configuration:")
            print("  runtime/persistent option: SET PERSIST audit_log.format_unix_timestamp = ON;")
            print("Note: changing audit_log.format_unix_timestamp rotates the audit log.")


def check_audit_installation(session=None):
    import mysqlsh
    global audit_on

    session = fetch_session(session)
    if session is None:
        return False

    print("\n\n***** Checking for MySQL Enterprise Audit")

    try:
        plugin_ok = audit_plugin_installed(session)
        component_ok = audit_component_installed(session)
    except Exception as e:
        print("Error checking audit installation: " + str(e))
        audit_on = False
        return False

    if plugin_ok:
        print("MySQL Enterprise Audit plugin is installed and active")
    else:
        print("MySQL Enterprise Audit plugin is not installed and active")

    if component_ok:
        print("MySQL Enterprise Audit component is installed")
    else:
        print("MySQL Enterprise Audit component is not installed")

    if not plugin_ok and not component_ok:
        print("Neither the audit_log plugin nor component_audit_log is installed")
        audit_on = False
        return False

    if not audit_filter_tables_installed(session):
        print("MySQL Enterprise Audit filter tables are not installed")
        print("Expected mysql.audit_log_filter and mysql.audit_log_user")
        audit_on = False
        return False

    print("Audit filter tables are installed")

    function_count = audit_loadable_functions_installed(session)
    if plugin_ok and function_count == 0:
        print("Warning: no audit_log_* loadable functions were found in mysql.func")
        print("The plugin install script may need to be rerun to load the SQL functions")
    elif function_count > 0:
        print("Audit loadable functions are installed")
    elif component_ok:
        print("Audit component mode detected; audit_log_* functions are registered by the component")

    check_audit_recommended_settings(session, plugin_ok=plugin_ok, component_ok=component_ok)

    audit_on = True
    return True
    



@plugin_function('audittool.start.wizard')
def start_wizard(**kwargs):
    """Start STIG CHECKS in the Plugin

    This function will list all CHECKS referencing 
    Vul ID, Rule ID, STIG ID, Severity, Classification, Rule Title	   

    Args:
        **kwargs: Optional parameters

    Keyword Args:
        connection_uri (str): The URI to the MySQL Server
        return_formatted (bool): If set to true, a list object is returned.

    Returns:
        A list of DISA STIG MySQL 8.0 Enterprise Edition checks in this tool
    """


    config = kwargs.get("config")
    interactive = kwargs.get("interactive", True)
    return_formatted = kwargs.get("return_formatted", True)

    if(check_audit_installation()):
        print("MySQL Enterprise Audit is installed")
    else:
        print("MySQL Enterprise Audit is not properly installed")
        return
    print("\n\n")

    rep=True
    while (rep):        
        print("What do you want to do?")
        print("1 - Show audit filters")
        print("2 - Create a new audit filter")
        print("3 - Delete an audit filter")
        print("4 - Show users and filter")
        print("5 - Add users to an audit filter")
        print("6 - Delete users from an audit filter")
        print("7 - Quit ")

        sel = check_user_input_pos_int("Selection")
        if(sel == '1'):
            show_audit_filters()
        if(sel == '2'):    
            new_audit_filters()
        if(sel == '3'):    
            del_audit_filters()
        if(sel == '4'):    
            show_user_audit_filters()
        if(sel == '5'):    
            add_user_audit_filters()
        if(sel == '6'):    
            del_user_audit_filters()
        if(sel == '7'):
            print('Exiting')
            rep=False
        print("\n-------------------------------------------------------\n")

    print("Done")

