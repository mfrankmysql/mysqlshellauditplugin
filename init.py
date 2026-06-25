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

"""Plugin registration

This file is automatically loaded by the MySQL Shell at startup time.

It registers the plugin objects and then imports all sub-modules to
register the plugin object member functions.
"""

from mysqlsh.plugin_manager import plugin


# Create a class representing the structure of the plugin and use the
# @register_plugin decorator to register it
@plugin
class audittool():
    """Plugin to run security_checks.

    This global object exposes a list of check options
    to work with audittools required by DISA and CIS and others
    """

    def __init__(self):
        """Constructor that will import all relevant sub-modules

        The constructor is called by the @plugin decorator to 
        automatically register all decorated functions in the sub-modules
        """
        # Import all sub-modules to register the decorated functions there
        from audittool_plugin import wizard 
#        from audittool_plugin import compartment, compute, configuration, general
#        from audittool_plugin import mysql_database_service, network, object_store
#        from audittool_plugin import user

    class start():
        """Used to list audittool objects.
        """

