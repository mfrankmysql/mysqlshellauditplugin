# Copyright (c) 2026 Mike
# SPDX-License-Identifier: UPL-1.0
#
# This is an independent community MySQL Shell plugin. It is not part of
# MySQL, MySQL Shell, Oracle, or any official MySQL source tree.
#
# Distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the LICENSE file for details.

"""Plugin registration for the independent audittool MySQL Shell plugin.
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

