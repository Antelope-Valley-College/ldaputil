#!/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import ldap3
import sys
import getpass

def add_source_arg_parsers(parser):
    parser.add_argument('host', help = 'The LDAP host to connect to.  Can be an LDAP string, which is used to enable LDAPS.')
    parser.add_argument('username', help = 'The bind name for the LDAP connection. May be "*" to prompt the console for a username.')
    parser.add_argument('password', help = 'The password for the LDAP connection. May be "*" to prompt the console for a password.')
    
def add_query_arg_parsers(parser):
    parser.add_argument('search_base', help = 'The base DN of the object to search from')
    parser.add_argument('query', help = 'An LDAP filter statement used to select objects')

def process_args():
    parser = argparse.ArgumentParser(description = 'LDAP swiss army utility.', epilog = 'To get help on a command, use the arguments "{command} -h"')
    action_parser = parser.add_subparsers(dest='action', help = 'action the utility is to perform')
    count_parser = action_parser.add_parser('count', help = 'count the number of objects selected by a filter')
    add_source_arg_parsers(count_parser)
    add_query_arg_parsers(count_parser)
    read_parser = action_parser.add_parser('read', help = 'display objects selected by a filter')
    add_source_arg_parsers(read_parser)
    add_query_arg_parsers(read_parser)
    read_parser.add_argument('fields', nargs='*', help = 'An optional space separated list of field names to display')
    csv_parser = action_parser.add_parser('csv', help = 'output objects selected by a filter in csv format')
    add_source_arg_parsers(csv_parser)
    add_query_arg_parsers(csv_parser)
    csv_parser.add_argument('fields', nargs='*', help = 'An optional space separated list of field names to display')
    get_parser = action_parser.add_parser('get', help = 'get the contents of a field for objects')
    add_source_arg_parsers(get_parser)
    add_query_arg_parsers(get_parser)
    get_parser.add_argument('field', help = 'The field to return from selected objects')
    add_parser = action_parser.add_parser('add', help = 'add a new value to a field for objects')
    add_source_arg_parsers(add_parser)
    add_query_arg_parsers(add_parser)
    add_parser.add_argument('field', help = 'The field to add a value to for selected objects')
    add_parser.add_argument('value', help = 'The value to add')
    replace_parser = action_parser.add_parser('replace', help = 'if a value is found in field in objects, replace it with a new value')
    add_source_arg_parsers(replace_parser)
    add_query_arg_parsers(replace_parser)
    replace_parser.add_argument('field', help = 'The field to replace a value in for selected objects')
    replace_parser.add_argument('old_value', help = 'The value to replace')
    replace_parser.add_argument('new_value', help = 'The replacement value')
    remove_parser = action_parser.add_parser('remove', help = 'remove a value if it is found in field for objects')
    add_source_arg_parsers(remove_parser)
    add_query_arg_parsers(remove_parser)
    remove_parser.add_argument('field', help = 'The field to remove a value from for selected objects')
    remove_parser.add_argument('value', help = 'The value to remove if present')
    set_parser = action_parser.add_parser('set', help = 'set field for objects so it only contains one value')
    add_source_arg_parsers(set_parser)
    add_query_arg_parsers(set_parser)
    set_parser.add_argument('field', help = 'The field to set a value in for selected objects')
    set_parser.add_argument('value', help = 'The value to set')
    empty_parser = action_parser.add_parser('empty', help = 'completely purge and delete field for objects')
    add_source_arg_parsers(empty_parser)
    add_query_arg_parsers(empty_parser)
    empty_parser.add_argument('field', help = 'The field to purge for selected objects')
    group_parser = action_parser.add_parser('group', help = 'modify the members of a group object based on a objects selected by a filter')
    add_source_arg_parsers(group_parser)
    group_parser.add_argument('group_dn', help = 'The DN of the group to be modified')
    add_query_arg_parsers(group_parser)
    return parser.parse_args()


def main():
    arg_list = process_args()
    process(arg_list)

def process(arg_list):
    if arg_list.action == 'count':
        ldap_count(arg_list)
    elif arg_list.action == 'read':
        ldap_read(arg_list)
    elif arg_list.action == 'csv':
        ldap_export(arg_list)
    elif arg_list.action == 'get':
        ldap_get(arg_list)
    elif arg_list.action == 'add':
        ldap_add(arg_list)
    elif arg_list.action == 'remove':
        ldap_remove(arg_list)
    elif arg_list.action == 'replace':
        ldap_replace(arg_list)
    elif arg_list.action == 'set':
        ldap_set(arg_list)
    elif arg_list.action == 'empty':
        ldap_empty(arg_list)
    elif arg_list.action == 'group':
        ldap_group(arg_list)

def get_connection(arg_list):
    try:
        if arg_list.username == '*':
            username = ''
            username = getpass.getpass('Username:')
        else:
            username = arg_list.username
        assert username != ''
        if arg_list.password == '*':
            password = ''
            password = getpass.getpass('Password:')
        else:
            password = arg_list.password
        assert password != ''
    except:
        print ('Both the bind username and password must not be empty.')
        sys.exit()

    try:
        if '://' in arg_list.host:
            server = ldap3.Server(arg_list.host, get_info= ldap3.ALL)
        else:
            server = ldap3.Server(arg_list.host, port = 389, get_info= ldap3.ALL)
        return ldap3.Connection(server, auto_bind=True, client_strategy = ldap3.SYNC, user = username, password=password, authentication=ldap3.SIMPLE, check_names=True)
    except RuntimeError as error_message:
        print ('Unable to connect.' , error_message)
        sys.exit()

def ldap_raw_read(arg_list):
    scope = ldap3.SUBTREE
    result_set = {}
    fields = tuple(map(str.lower,arg_list.fields))
    attr_list = ldap3.ALL_ATTRIBUTES if len(arg_list.fields) == 0 else fields
    all_attrs = len(arg_list.fields) == 0 or len(set(arg_list.fields) & set((ldap3.ALL_ATTRIBUTES,ldap3.ALL_OPERATIONAL_ATTRIBUTES))) > 1
    try:
        with get_connection(arg_list) as connection:
            connection.search(arg_list.search_base, arg_list.query, scope, attributes = attr_list)
            for entry in connection.entries:
                entry_hash = {}
                result_set[entry.entry_dn] = entry_hash
                for values in sorted(filter(lambda x:x.key.lower() in fields or all_attrs, entry), key=lambda x:x.key):
                    attributes = values.values[0] if isinstance(values.values, (list, tuple)) and len(values.values) == 1 else values.values
                    entry_hash[values.key] = attributes
    # except ldap3.LDAPException as error_message:
    except ldap3.core.exceptions.LDAPException as error_message:
        sys.stderr.write ('Search error %s'% error_message)
        sys.exit()
    return result_set

def ldap_read(arg_list):
    objects = ldap_raw_read(arg_list)
    for dn, entry in objects.items():
        print (dn)
        for name, attributes in entry.items():
            if not isinstance(attributes, (list, tuple)):
                print ("\t%s: %s" % (name, attributes))
            else:
                print ("\t%s" % name)
                for output in enumerate(attributes):
                    print ("\t\t%i: %s" % output)

def ldap_export(arg_list):
    objects = ldap_raw_read(arg_list)
    # Generate headers
    if len(arg_list.fields) == 0 or len(set(arg_list.fields) & set((ldap3.ALL_ATTRIBUTES,ldap3.ALL_OPERATIONAL_ATTRIBUTES))) > 1:    
        headers = sorted(set(sum([list(x.keys()) for x in objects.values()],[])))
    else:
        headers = arg_list.fields
    # Write CSV headers
    print (','.join(map(lambda x:'"%s"'%x,headers)))
    for dn, entry in objects.items():
        try:
            # Create value accumulator
            line = []        
            # Iterate through all headers in order
            for key in headers:            
                # Verify that there is a value for this attribute
                if key in entry:
                    # Specifically grab values
                    attributes = entry[key]
                    # Check if value is an array
                    if not isinstance(attributes, (list, tuple)):
                        # Not an array, collect value
                        line.append('"%s"'%attributes)
                    elif len(attributes) == 0:
                        line.append('')
                    else:
                        # Is an array, collect first value only
                        line.append('"%s"'%(';'.join(map(str,attributes))))
                else:
                    # The specified attribute does not exist in this object.
                    # Collect an empty string to pad columns properly.
                    line.append('')
            # Write this line of data.
            print (','.join(line))
        except BaseException as e:
            sys.stderr.write("Error: {}\n{}\n".format(e, repr(line)))

def ldap_count(arg_list):
    scope = ldap3.SUBTREE
    try:
        with get_connection(arg_list) as connection:
            connection.search(arg_list.search_base, arg_list.query, scope, attributes = [])
            print (len(connection.entries))
    except ldap3.core.exceptions.LDAPException as error_message:
        sys.stderr.write ('Search error %s\n'% error_message)        

def ldap_modify(arg_list, function): #connection, base, query, attr, command, value
    scope = ldap3.SUBTREE
    correctMe = True
    count = 0
    try:
        with get_connection(arg_list) as connection:
            connection.search(arg_list.search_base, arg_list.query, scope, attributes = [arg_list.field])
            total=len(connection.entries)
            for index,entry in enumerate(connection.entries):
                #print (dir(entry))
                if correctMe:
                    for o in entry:
                        if str.lower(o.key) == str.lower(arg_list.field):
                            attr = o.key
                            correctMe = False
                            break
                modlist = function(arg_list, entry, attr)
                if len(modlist)>0:
                    sys.stdout.write("%i of %i Updating %s "%(index+1,total,entry.entry_dn))
                    #print (modlist)
                    result=connection.modify(entry.entry_dn,modlist)
                    #print (result)
                    if result:
                        count=count+1
                        print ("OK")
                    else:
                        print ("Error: {}".format(connection.last_error))
            print ("%i accounts changed."%(count,))
    except ldap3.core.exceptions.LDAPException as error_message:
        sys.stderr.write ('Search error %s\n'% error_message)
        sys.stderr.write ('%r\n'% sys.argv)
        raise

def ldap_get(arg_list):
    def fxn(arg_list, entry, attr):
        print ("{}:".format(entry.entry_dn))
        if attr in entry.entry_attributes_as_dict:            
            for item in entry[attr]:
                print ("  {}".format(item))
            return []
        return []
    ldap_modify(arg_list, fxn)

def ldap_set(arg_list):
    def fxn(arg_list, entry, attr):
        return {attr:[(ldap3.MODIFY_REPLACE,[arg_list.value.encode('utf_16_le')])]}
    ldap_modify(arg_list, fxn)

def ldap_add(arg_list):
    def fxn(arg_list, entry, attr):
        if attr in entry.entry_attributes_as_dict and arg_list.value in entry[attr].values:
            print ("%i of %i Updating %s Already present"%(index+1,total,entry.entry_dn))
            return []
        return {attr:[(ldap3.MODIFY_ADD,[arg_list.value.encode('utf_16_le')])]}
    ldap_modify(arg_list, fxn)

def ldap_remove(arg_list):
    def fxn(arg_list, entry, attr):
        if attr not in entry.entry_attributes_as_dict or arg_list.value not in entry[attr].values:
            print ("%i of %i Updating %s Already missing"%(index+1,total,entry.entry_dn))
            return []
        return {attr:[(ldap3.MODIFY_DELETE,[arg_list.value.encode('utf_16_le')])]}
    ldap_modify(arg_list, fxn)

def ldap_replace(arg_list):
    def fxn(arg_list, entry, attr):
        if attr not in entry.entry_attributes_as_dict or arg_list.old_value not in entry[attr].values:
            print ("%i of %i Updating %s Not present"%(index+1,total,entry.entry_dn))
            return []
        return {attr:[(ldap3.MODIFY_DELETE,[arg_list.old_value]),(ldap3.MODIFY_ADD,[arg_list.new_value])]}
    ldap_modify(arg_list, fxn)

def ldap_empty(arg_list):
    def fxn(arg_list, entry, attr):
        if attr not in entry.entry_attributes_as_dict:
            print ("%i of %i Updating %s Already empty"%(index+1,total,entry.entry_dn))
            return []
        return {attr:[(ldap3.MODIFY_DELETE,[entry[attr].values])]}
    ldap_modify(arg_list, fxn)

def ldap_group(arg_list):
    scope = ldap3.SUBTREE
    correctMe = True
    count = 0
    try:
        with get_connection(arg_list) as connection:
            # Search for what should be in the list.
            connection.search(arg_list.search_base, arg_list.query, scope, attributes = [])
            # Get the objects that should be in the group.
            new_membership = set(map(lambda x:x.entry_dn, connection.entries))
            print (new_membership)
            # Get the group object
            connection.search(arg_list.group_dn, '(objectClass=*)', ldap3.BASE, attributes = ['member'])
            if len(connection.entries) != 1:
                print ('Must only operate on one group, {0} found'.format(len(connection.entries)))
                return
            group = connection.entries[0]            
            # Get the objects that are in the group.
            old_membership = set(group.member if 'member' in group else [])
            # Identify changes
            additions = new_membership - old_membership
            removals = old_membership - new_membership
            print ("Changes: {} adds, {} deletes".format(len(additions),len(removals)))
            # Build one object to mass update the group in one call.
            changes = []
            if len(additions) > 0:
                changes.append((ldap3.MODIFY_ADD, additions))
            if len(removals) > 0:
                changes.append((ldap3.MODIFY_DELETE, removals))
            if len(changes) == 0:
                print ("No changes needed.")
                return
            # Perform the update.
            update = {'member':changes}
            result=connection.modify(group.entry_dn, update)            
            if result:
                print ("Updated all.")
            else:
                print ("Error: {}".format(connection.last_error))
    except ldap3.core.exceptions.LDAPException as error_message:
        sys.stderr.write ('Search error %s\n'% error_message)        
        raise

if __name__=='__main__':
    main()
