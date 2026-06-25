# Copyright (c) 2020, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is also distributed with certain software (including
# but not limited to OpenSSL) that is licensed under separate terms, as
# designated in a particular file or component or in included license
# documentation.  The authors of MySQL hereby grant you an additional
# permission to link the program and your derivative works with the
# separately licensed software that they have included with MySQL.
# This program is distributed in the hope that it will be useful,  but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
# the GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

"""Sub-Module for supporting DISA STIG Checks"""


from mysqlsh.plugin_manager import plugin_function

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


def check_user_name(uname, uhost, session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")
    fullname = uname + "\uFF20" + uhost
    fnduser = "select count(user) as cname from mysql.user where concat(user,'\uFF20',host)='"+ fullname + "' group by user"
    print (fnduser)
    n_ok=False
    r = session.run_sql(fnduser)
    o=r.fetch_all()
    num_name = int(o[0][0])
    if(num_name > 0):
        n_ok = True
    else:
        n_ok = False
    return n_ok


    
def check_user_input_pos_int(prompt):
    intnotok=True
    val=0
    while intnotok == True:
        input_str = input(prompt)
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
        input_str = input(prompt)
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

def show_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    r = session.run_sql("select * from mysql.audit_log_filter")
    if shell.dump_rows(r) > 0:
        print(' ')
    else:
       print("No audit filters")
    return

def name_filter(session):
    namenotok=True
    while (namenotok):
        fname = input("Please name your filter : ")
        name_exists="select count(*) as num_name from mysql.audit_log_filter where name = '" + fname + "'" 
        r = session.run_sql(name_exists)
        o=r.fetch_one()
        num_tabs = o.get_field("num_name")
        if(num_tabs > 0):
            print("Name exists - please use a different name")
            namenotok=True
        else:    
            if(check_user_input_y_n("Is that a good name (Y/N)") == 'Y'):
                namenotok=False
            else:
                namenotok=True
    return fname

def check_schema_name(session):
    namenotok=True
    while (namenotok):
        fname = input("Schema Name : ")
        name_exists="select count(*) as num_name from information_schema.schemata where schema_name= '" + fname + "'" 
        r = session.run_sql(name_exists)
        o=r.fetch_one()
        num_tabs = o.get_field("num_name")
        if(num_tabs > 0):
            namenotok=False
        else:
            print("No database/schema of that name exists - please try again")
            namenotok=True
    return fname

def check_schema_for_table_name(session, schem):
    namenotok=True
    while (namenotok):
        fname = input("Table Name : ")
        name_exists="select count(*) as num_name from information_schema.tables where table_schema='" + schem + "' and table_name='" + fname + "'" 
        r = session.run_sql(name_exists)
        o=r.fetch_one()
        num_tabs = o.get_field("num_name")
        if(num_tabs > 0):
            namenotok=False
        else:
            print("No table in the selected database/schema of that name exists - please try again")
            namenotok=True
    return fname


def filter_log_everything(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Audit Log Everything Filter")
    
    print("1 - Everything")
    print("2 - Only Errors - for example the access is denied")
    print("3 - All Fails")
    filt_name = name_filter(session)
    fjson = '{ "filter": { "log": true } }'
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")    

    return


def wb_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Audit Log Everything Filter")
    
    filt_name = name_filter(session)
    fjson = '{ "filter": { "class": [ { "name": "connection", “connection_data": [ { "program_name": "MySQLWorkbench","log","true" } ] } ] } }'
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")    
    return

def filter_log_connections_only(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Connection Audit Logging Filter")
    print("Do you want to Log")
    print("1: All Connections")
    print("2: Only Failed Connections")
    print("3: Only Successful Connections")
    print("4: All Connections/Disconnections")
  
    pick = check_user_input_pos_int("Enter 1, 2, or 3")
    fjson=" "
    all_connections = '{ "filter": { "class": { "name": "connection" } } }'
    failed_connections = '{ "filter": { "class": { "name": "connection", "event": { "name": "connect", "log": { "not": { "field": { "name": "status", "value": 0 } } } } } } }'
    successful_connections = '{ "filter": { "class": { "name": "connection", "event": { "name": "connect", "log": { "field": { "name": "status", "value": 0 } }  } } } }'
    
    if(pick == '1'):
        fjson=all_connections
        print("Audit All Connections")
    elif(pick == '2'):
        fjson=failed_connections
        print("Audit Failed Connections")
    elif(pick == '3'):
        fjson=successful_connections
        print("Audit Successful Connections")

    filt_name = name_filter(session)
    
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")    
    return

def filter_by_table_dml_type (session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Audit Log for Tables and DML types")
    fjson = """          
{ 
  "filter":
  {
   "id": "main",
   "class":
   {
      "name": "table_access",
      "event":
    {
      "name": [ """
    print("Please select 1-4 DML event types you wish to capture")
    capevent=" "
    commacnt = 0
    if(check_user_input_y_n ("INSERTs? Y/N")):
        capevent = capevent + '"insert"'
        commacnt += 1
    if(check_user_input_y_n ("UPDATEs? Y/N")):
        if (commacnt > 0):
            capevent = capevent + ','
        capevent = capevent + '"update"'
        commacnt += 1
    if(check_user_input_y_n ("DELETEs? Y/N")):        
        if (commacnt > 0):
            capevent = capevent + ','
        capevent = capevent + '"delete"'
        commacnt += 1
    if(check_user_input_y_n ("READs? Y/N")):
        if (commacnt > 0):
            capevent = capevent + ','
        capevent = capevent + '"read"'
    fjson = fjson + capevent
    fjson = fjson +  """],
      "log": false,
      "filter":
      {
        "activate": { "or": [ """
    print("Provide schema and table name for targeted auditing")
    moretables=True
    while (moretables):
        schname = check_schema_name(session)
        tblname = check_schema_for_table_name(session, schname)
        fjson = fjson + """ { "and": [ { "field": { "name": "table_database.str", "value": """
        fjson = fjson + '"' + schname + '"'
        fjson = fjson + """ } }, { "field": { "name": "table_name.str", "value": """
        fjson = fjson + '"' + tblname + '"'
        fjson = fjson + """ } } ] }  """
        rans = check_user_input_y_n("Any additional tables")
        if(rans == 'Y'):
            fjson = fjson + """ , """
            moretables=True
        else:
            fjson = fjson + " ] }, "
            moretables=False
        

    fjson = fjson + """ "class": { "name": "general",
          "event":
           {
             "name": "status",
             "log": { "not": { "field": { "name": "general_error_code", "value": 0 } } },
             "filter": { "ref": "main" }
           }
        }
      }
    }
   }
  }
}""" 
    print (fjson)
    filt_name = name_filter(session)
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")
    return




def filter_by_ddl_type(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Audit Log for - Specific DDL Actions - Filter")
    fjson = """
{
"filter": {
  "class": {
    "name": "general",
    "event": {
      "name": "status",
      "log": {
        "and": [
        {
           "or": [
           {"field": { "name": "general_command.str", "value": "Query" }},
           {"field": { "name": "general_command.str", "value": "Execute" }}
           ]
        },
       {
          "or": ["""
    print("Please select the DDL event types you wish to capture")
    capevent=" "
    commacnt = 0
    ddladd =[]
    if(check_user_input_y_n ("alter_dbs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_db" }}')
        commacnt += 1
    if(check_user_input_y_n ("alter_db_upgrades? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_db_upgrade" }}')
        commacnt += 1
    if(check_user_input_y_n ("alter_events? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_event" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_functions? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_function" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_instances? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_instance" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_procedures? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_procedure" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_servers? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_server" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_tables? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_table" }}')    
        commacnt += 1
    if(check_user_input_y_n ("alter_tablespaces? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "alter_tablespace" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_dbs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_db" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_events? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_event" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_functions? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_function" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_indexs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_index" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_procedures? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_procedure" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_servers? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_server" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_tables? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_table" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_triggers? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_trigger" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_udfs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_udf" }}')    
        commacnt += 1
    if(check_user_input_y_n ("create_views? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "create_view" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_dbs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_db" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_events? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_event" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_functions? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_function" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_indexs? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_index" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_procedures? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_procedure" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_servers? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_server" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_tables? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_table" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_triggers? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_trigger" }}')    
        commacnt += 1
    if(check_user_input_y_n ("drop_views? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "drop_view" }}')    
        commacnt += 1
    if(check_user_input_y_n ("rename_tables? - Y/N")): 
        ddladd.append('          {"field": { "name": "general_sql_command.str", "value": "rename_table" }}')    
        commacnt += 1

    lastjson = """
          ]
       }
    ]
    }
   }
  }
 }
}
"""
    addcnt=0
    for ddlitem in ddladd:
        fjson = fjson + ddlitem
        addcnt += 1
        print (addcnt)
        print (commacnt)
        if (addcnt < commacnt):
            fjson = fjson + ','
    fjson = fjson + lastjson
    print (fjson)
    filt_name = name_filter(session)
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")
    return


def filter_access_failures(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("Creating Audit Log for - Any unsuccessful accesses to objects - Filter")
    
    filt_name = name_filter(session)
    fjson = '{ "filter": { \
    "class": { \
    "name": "general", \
    "event": { \
    "name": "status", "log": { \
    "not": { "field": { "name": "general_error_code", "value": 0 }} } \
    } } \
    } }'
    fstmt = "SELECT audit_log_filter_set_filter('" + filt_name + "','" + fjson + "')"
    print (fstmt)
    r = session.run_sql(fstmt)
    if shell.dump_rows(r) > 0:
        print('Created')
    else:
       print("Failed to create")    
    return

def new_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    rep=True
    while (rep):        
        print("What types actions do you wish to collect in the audit log?")
        print("1 - Log Everyting")
        print("2 - Connections")
        print("3 - Security Access Failures")
        print("4 - Table Name and SQL type")
        print("5 - DDL")
        print("6 - Security Controls and DCL")
        print("7 - ")
        print("8 - Merge Filters???")
        print("9 - ")
        print("10 - Return")
        sel = check_user_input_pos_int("Selection : ")
        if(sel == '1'):
            print('1')
            filter_log_everything()
        if(sel == '2'):
            print('2')
            filter_log_connections_only()
        if(sel == '3'):    
            print('3')
            filter_access_failures()
        if(sel == '4'):    
            print('4')
            filter_by_table_dml_type()
        if(sel == '5'):    
            print('5')
            filter_by_ddl_type()
        if(sel == '6'):    
            print('6')
#            add_user_audit_filters()
        if(sel == '7'):    
            print('7')
            wb_audit_filters()
        if(sel == '8'):
            print('8')
            rep=False
        if(sel == '9'):
            print('9')
            rep=False
        if(sel == '10'):
            print('10')
            rep=False

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
    if n is not None:
        while n is not None:
            if (n.get_field("ucnt") > 0):                
                cantdellist.append(n.get_field("fname") + " \t\t- has " + str(n.get_field("ucnt")) + " user(s) assigned - unable to remove")
            else:
                dellist.append(n.get_field("fname"))
            n = r.fetch_one()
    else:
        print("No filters in place")
    
    print("------------------------------------------------------------------------")
    print("These filters have users please remove the users if you wish to delete.")
    for filt in cantdellist:
        print(filt)
    print("")
    print("------------------------")
    print("Select filters to remove")
    filindex=1
    for filt in dellist:
        rmfilt = " Do you wish to remove AUDIT FILTER - " + filt + " ? (Y/N)"
        rans = check_user_input_y_n(rmfilt)
        if(rans == 'Y'):
            delstr = "DELETE from mysql.audit_log_filter where name = '" + filt +"'"
            r=session.run_sql(delstr)
            shell.dump_rows(r)
            print("******")
        else:
            print("")
    return

def del_one_user_audit_filters( userhost, session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")
    atsign='@'
    delstr = "SELECT audit_log_filter_remove_user('" + userhost + "')"
    delu = session.run_sql(delstr)
    split_string = userhost. split("@", 1)
    if(exist_user_audit_filters(split_string[0],split_string[1])):
        print("Error - User/Filter was not removed")
    else:
        print("OK - User/Filter was removed")
    
    return

def del_user_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    r = session.run_sql("select user, host, filtername from mysql.audit_log_user")
    print("")
    print("------------------------")
    print("Select user/hosts to remove")

    i = 0
    deluserhostlist = []
    for n in session.run_sql("select user, host, filtername from mysql.audit_log_user").fetch_all():     
        i = i + 1   
        u=n[0]
        h=n[1]
        fn=n[2]
        atsign='@'
        rmfilt = "Do you wish to remove the User AUDIT FILTER - User: " + u  + atsign + h + " Filter: " + fn + " ? (Y/N)"
        rans = check_user_input_y_n(rmfilt)

        if(rans == 'Y'):
            deluserhostlist.append(u+atsign+h)

    
        for rmuserhost in deluserhostlist:
            del_one_user_audit_filters(rmuserhost)
    else:
        print("No users assigned to filters")
    return

def show_user_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")

    r = session.run_sql("select * from mysql.audit_log_user")
    if shell.dump_rows(r) > 0:
        print(' ')
    else:
       print("No users")


    return

def exist_user_audit_filters(uname, hname, session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    exists=False
    if session is None:
        return
    print("")

    r = session.run_sql("select * from mysql.audit_log_user where USER ='" + uname +"' and HOST ='" + hname + "'")
    print("select * from mysql.audit_log_user where USER ='" + uname +"' and HOST ='" + hname + "'")
    x = r.fetch_one()
    print(x)
    if x is not None:
        exists = True
    else:
        exists = False


    return exists

def add_user_audit_filters(session=None):
    import mysqlsh
    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return
    print("")
    r = session.run_sql("select name from mysql.audit_log_filter")
    if shell.dump_rows(r) > 0:
        print(' ')
    else:
       print("No audit filters")
    
    filterok=1
    while filterok == 1:
        pickfilter=input("Enter a filter name from the above list : ")
        r = session.run_sql("select count(name) from mysql.audit_log_filter where name = '" + pickfilter + "'")
        fexist = r.fetch_one()
        print(fexist[0])
        if (fexist[0] == 1):
            print("Enter the user name then the host name")
            username = input("Enter User Name : ")
            hostname = input("Enter Hostname : ")
            print(username)
            if(check_user_name(username, hostname)):
                print('Full User Account Name is confirmed - Adding User to Filter')
                atsign = '@'
                add_filter = "SELECT audit_log_filter_set_user('" + username + atsign + hostname + "','" + pickfilter +"')"
                print(add_filter)
                rcuf=session.run_sql(add_filter)
                if(exist_user_audit_filters(username,hostname)):
                    print("OK - User/Filter Confirmed")
                else:
                    print("Error - User/Filter not added")
# add check later once function can throw and error 
            else:
                print("Full Name is not ok")
            filterok=0
        else:
            print("Bad filter name please re-enter.")
            filterok=1
    return



def check_audit_installation(session=None):
    import mysqlsh
    global audit_encryption
    global audit_on

    shell = mysqlsh.globals.shell
    session = fetch_session(session)
    if session is None:
        return False

    print("\n\n***** Checking for Audit Plugin ")
    try:
        r = session.run_sql("SELECT `PLUGIN_NAME`, `PLUGIN_STATUS`, `PLUGIN_TYPE`, `PLUGIN_LIBRARY`, `PLUGIN_DESCRIPTION`, `LOAD_OPTION` "
                " FROM `information_schema`.`PLUGINS` where PLUGIN_NAME LIKE 'audit_log' and plugin_status='ACTIVE'")
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    if shell.dump_rows(r) > 0:
        print("MySQL Auditing Plugin is installed and active")
        audit_on=True
        r = session.run_sql("select count(*) as num_atabs  from information_schema.tables where table_schema='mysql' and table_name like 'audit%'")
        o=r.fetch_one()
        num_tabs = o.get_field("num_atabs")
        if(num_tabs > 1): 
            print("Audit Tables are installed")
            audit_tables=True
            print("The following audit functions are installed")
            r = session.run_sql("select `name` from mysql.func where name like 'audit_log%'")
            if(shell.dump_rows(r) > 0):
                print("OK - functions are installed")
            else:
                print("No auditing functions have been installed")
        else:
            print("MySQL Audit Tables are not installed")
            audit_tables=False
            return False
    else:
        print("MySQL Auditing plugin is NOT installed and active")
        audit_on=False
        return False

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

        sel = check_user_input_pos_int("Selection : ")
        if(sel == '1'):
            print('1')
            show_audit_filters()
        if(sel == '2'):    
            print('2')
            new_audit_filters()
        if(sel == '3'):    
            print('3')
            del_audit_filters()
        if(sel == '4'):    
            print('4')
            show_user_audit_filters()
        if(sel == '5'):    
            print('5')
            add_user_audit_filters()
        if(sel == '6'):    
            del_user_audit_filters()
        if(sel == '7'):
            print('Exiting')
            rep=False
        print("\n-------------------------------------------------------\n")

    print("Done")

