import ldap3

s = ldap3.Server('192.168.11.150')
c = ldap3.Connection(
        s, 
        auto_bind=True, 
        client_strategy=ldap3.STRATEGY_SYNC, 
        user='cn=admin,dc=hamlet,dc=twopicode,dc=local', 
        password='78e3aa97f21af80a62780288664a661e', 
        authentication=ldap3.AUTH_SIMPLE, 
        check_names=True)
# print(c)
# print(c.search('ou=gymea-h,dc=hamlet,dc=twopicode,dc=local', '(uid=jjimson)', ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=['mail']))
# print (c.result)
# print (c.response)

# print(c.search('ou=gymea-h,dc=hamlet,dc=twopicode,dc=local', '(memberUid=jjimson)', ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=ldap3.ALL_ATTRIBUTES))
# print (c.result)
# print (c.response)

c.search('ou=groups,ou=gymea-h,dc=hamlet,dc=twopicode,dc=local', '(objectClass=posixGroup)', ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=ldap3.ALL_ATTRIBUTES)
# print (c.result)
# print (c.response)
for group in c.response:
        print (group)

# print ("Trying Bind")

# direct_conn = ldap3.Connection(
#                 s, 
#                 auto_bind=True, 
#                 client_strategy=ldap3.STRATEGY_SYNC, 
#                 user='cn=Jimmy Jimson,ou=students,ou=gymea-h,dc=hamlet,dc=twopicode,dc=local', 
#                 password='ZenSVR11', 
#                 authentication=ldap3.AUTH_SIMPLE, 
#                 check_names=True)
# print (direct_conn)