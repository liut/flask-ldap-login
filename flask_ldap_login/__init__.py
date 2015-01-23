"""
Configuration Variables
-----------------------

To set the flask-ldap-login config variables

update the application like::

    app.config.update(LDAP={'URI': ..., })
 
:param URI: 
    Start by setting URI to point to your server. 
    The value of this setting can be anything that your LDAP library supports. 
    For instance, openldap may allow you to give a comma- or space-separated 
    list of URIs to try in sequence.
    
:param BIND_DN:
    The distinguished name to use when binding to the LDAP server (with BIND_AUTH). 
    Use the empty string (the default) for an anonymous bind. 

:param BIND_AUTH:
    The password to use with BIND_DN
    
:param USER_SEARCH:
    An  dict that will locate a user in the directory.
    The dict object may contain 'base' (required), 'filter' (required) and 'scope' (optional)
    base: The base DN to search
    filter:  Should contain the placeholder %(username)s for the username.
    scope:  
     
    e.g.::
        {'base': 'dc=continuum,dc=io', 'filter': 'uid=%(username)s'}
        
:param KEY_MAP:
    This is a dict mapping application context to ldap.
    An application may expect user data to be consistent and not all ldap
    setups use the same configuration::
     
        'application_key': 'ldap_key'   


"""
import logging

import flask
import ldap3

from .forms import LDAPLoginForm

log = logging.getLogger(__name__)

def scalar(value):
    """
    Take return a value[0] if `value` is a list of length 1 
    """
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return value[0]
    return value


class LDAPLoginManager(object):
    '''
    This object is used to hold the settings used for LDAP user lookup. Instances of
    `LDAPLoginManager` are *not* bound to specific apps, so you can create
    one in the main body of your code and then bind it to your
    app in a factory function.
    '''

    def __init__(self, app=None):

        if app is not None:
            self.init_app(app)

        self.conn = None
        self.server = None

        self._save_user = None


    def init_app(self, app):
        '''
        Configures an application. This registers an `after_request` call, and
        attaches this `LoginManager` to it as `app.login_manager`.
        '''

        self._config = app.config.get('LDAP', {})
        app.ldap_login_manager = self

        self.config.setdefault('BIND_DN', '')
        self.config.setdefault('BIND_AUTH', '')
        self.config.setdefault('URI', 'ldap://127.0.0.1')

        if self.config.get('USER_SEARCH') and not isinstance(self.config['USER_SEARCH'], list):
            self.config['USER_SEARCH'] = [self.config['USER_SEARCH']]


    def format_results(self, results):
        """
        Format the ldap results object into somthing that is reasonable
        """
        if not results:
            return None
        userobj = results[0]['attributes']
        keymap = self.config.get('KEY_MAP')
        if keymap:
            d =  {key:scalar(userobj.get(value)) for key, value in keymap.items()}
            d['dn'] = results[0]['dn']
            return d
        else:
            d = {key:scalar(value) for key, value in userobj.items()}
            d['dn'] = results[0]['dn']
            return d

    def save_user(self, callback):
        '''
        This sets the callback for staving a user that has been looked up from from ldap. 
        The function you set should take a username (unicode) and and userdata (dict).

        :param callback: The callback for retrieving a user object.
        '''

        self._save_user = callback
        return callback

    @property
    def config(self):
        'LDAP config vars'
        return self._config

    @property
    def attrlist(self):
        'Transform the KEY_MAP paramiter into an attrlist for ldap filters'
        keymap = self.config.get('KEY_MAP')
        if keymap:
            return list(keymap.values())
        else:
            return None

    def make_server(self):
        'initialize ldap connection and set options'

        if not self.server:
            try:
                log.debug("Connecting to ldap server %s" % self.config['URI'])
                self.server = ldap3.Server(self.config.get('URI'), get_info = ldap3.GET_ALL_INFO)
            except Exception:
                log.debug("Connection to ldap server %s failed." % self.config['URI'])
                return None

        return True

    def make_connection(self):
        if self.conn and self.conn.last_error:
            self.conn = None

        if self.conn:
            return self.conn

        user = self.config['BIND_DN']
        bind_auth = self.config['BIND_AUTH']
        log.debug("Binding with the BIND_DN %s" % user)

        if not self.server:
            self.make_server()
        
        try:
            conn = ldap3.Connection(
                self.server, 
                auto_bind=True, 
                client_strategy=ldap3.STRATEGY_SYNC, 
                user=user,
                password=bind_auth, 
                authentication=ldap3.AUTH_SIMPLE, 
                check_names=True)
        except Exception:
            log.debug("Could not connect bind with the BIND_DN=%s" % user)
            self.conn = None
            return None

        self.conn = conn
        return conn

    def bind_search(self, username, password):
        """
        Bind to BIND_DN/BIND_AUTH then search for user to perform lookup. 
        """

        log.debug("Performing bind/search")

        ctx = {'username':username, 'password':password}
        conn = self.make_connection()
        print("lel {}".format(conn))
        if not conn:
            # A Connection could not be established.
            return None

        user_search = self.config.get('USER_SEARCH')

        results = None
        for search in user_search:
            base = search['base']
            filt = search['filter'] % ctx
            scope = search.get('scope', ldap3.SEARCH_SCOPE_WHOLE_SUBTREE,)
            
            log.debug("Search for base=%s filter=%s" % (base, filt))

            if conn.search(base, filt, scope, attributes=self.attrlist):
                results = conn.response
                log.debug("User with DN=%s found" % results[0]['dn'])
                try:
                    ldap3.Connection(
                        self.server, 
                        auto_bind=True, 
                        client_strategy=ldap3.STRATEGY_SYNC, 
                        user=results[0]['dn'], 
                        password=password, 
                        authentication=ldap3.AUTH_SIMPLE, 
                        check_names=True)
                except ldap3.core.exceptions.LDAPBindError:
                    log.debug("Username/password mismatch, continue search...")
                    results = None
                    continue
                else:
                    log.debug("Username/password OK")
                    break

        return self.format_results(results)


    def direct_bind(self, username, password):
        """
        Bind to username/password directly
        """
        log.debug("Performing direct bind")

        ctx = {'username':username, 'password':password}
        scope = self.config.get('SCOPE', ldap3.SEARCH_SCOPE_WHOLE_SUBTREE)
        user = self.config['BIND_DN'] % ctx

        self.make_server()

        try:
            log.debug("Binding with the BIND_DN %s" % user)
            # self.conn.simple_bind_s(user, password)
            direct_conn = ldap3.Connection(
                self.server, 
                auto_bind=True, 
                client_strategy=ldap3.STRATEGY_SYNC, 
                user=user, 
                password=password, 
                authentication=ldap3.AUTH_SIMPLE, 
                check_names=True)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            return None

        direct_search_result = direct_conn.search(
            search_base=user, 
            search_filter=None, 
            search_scope=scope, 
            attributes=self.attrlist)

        if not direct_search_result:
            return None

        results = direct_conn.response
        return self.format_results(results)




    def ldap_login(self, username, password):
        """
        Authenticate a user using ldap. This will return a userdata dict
        if successfull. 
        ldap_login will return None if the user does not exist or if the credentials are invalid 
        """
        if self.config.get('USER_SEARCH'):
            result = self.bind_search(username, password)
        else:
            result = self.direct_bind(username, password)
        return result


    def retrieve_posix_groups(self, dn, uid=None):
        """
        Retrieve Posix Groups
        Get a user's groups if a user is specified.
        """
        conn = self.make_connection()
        if conn:
            if uid:
                filt = '(memberUid={uid})'.format(uid=uid)
            else:
                filt = '(objectClass=posixGroup)'
            try:
                if conn.search(dn, filt, ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=ldap3.ALL_ATTRIBUTES):
                    return conn.response
                else:
                    return []
            except Exception:
                return []
        else:
            return []
