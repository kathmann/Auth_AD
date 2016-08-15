<?php
if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

/*
 * Originally from Auth_AD.
 * TODO: not PSR-2 compliant; lots of global search/replace needed!

 Auth_AD is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Auth_AD is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Auth_AD.  If not, see <http://www.gnu.org/licenses/>.

 Heavily modified by Rob Pomeroy, possibly in an unsafe way in relation
 to password	storage (see below).

 Requires PHP 5.4 >= 5.4.26, PHP 5.5 >= 5.5.10, PHP 5.6 >= 5.6.0, PHP 7

 Upon a succesful login, the session contains the following:
 $this->session->userdata('cn') contains the common name from the AD
 $this->session->userdata('username') contains the username as processed
 $this->session->userdata('dn') contains the distinguished name from the AD
 $this->session->userdata('logged_in') contains a boolean (true)
 $this->session->userdata('objectguid') contains the AD globally unique identifier - which is binary/hex
 $this->session->userdata('p') contains the encrypted password

 Note: we encrypt and store the user password, so that it's available
 for use as the "old" password in password resets (the only way for a
 non-domainadmin to do this under AD). We also use it for subsequent AD
 queries from other controllers. Because of this, we also initialize
 the encryption library, 'salting' the configured encryption key with the
 username.

 *
 */

/**
 * Auth_AD Class
 *
 * Simple Active Directory LDAP authentication library for Code Igniter.
 *
 * @package         Auth_AD
 * @author          Mark Kathmann <mark@stackedbits.com>
 * @author          Rob Pomeroy <rob@pomeroy.me>
 * @version         0.4.1
 * @link            http://www.stackedbits.com/
 * @link            http://www.sykescottages.co.uk/
 * @license         GNU Lesser General Public License (LGPL)
 * @copyright       Copyright © 2013 Mark Kathmann <mark@stackedbits.com>
 * @copyright       Copyright © 2016 Sykes Cottages Ltd <itis@sykescottages.co.uk>
 */

class Auth_AD
{
    // register properties
    private $_hosts;
    private $_ports;
    private $_base_dn;
    private $_ad_domain;
    private $_start_ou;
    private $_new_user_ou;
    private $_shared_mbox_ou;
    private $_proxy_user;
    private $_proxy_pass;
    private $_admin_group;
    private $_ldap_conn;

    /**
     * @access public
     */
    public function __construct()
    {
        // start the first initialisation
        $this -> ci = &get_instance();
        log_message('debug', 'Auth_AD initialising');

        // load the configuration file
        $this -> ci -> load -> config('auth_ad');

        // load the necessary libraries
        $this -> ci -> load -> library('session');
        $this -> ci -> load -> library('encryption');

        // perform the secondary initialisation
        $this -> _init();
    }

    /**
     * @access private
     */
    private function _init()
    {
        // check for an active LDAP extension
        if (!function_exists('ldap_connect')) {
            log_message('error', 'Auth_AD: LDAP PHP module not found.');
            show_error('LDAP PHP module not found. Please ensure that the module is loaded or compiled in.');
        }

        // register the configuration variables as properties
        $this -> _hosts = $this -> ci -> config -> item('hosts');
        $this -> _ports = $this -> ci -> config -> item('ports');
        $this -> _tls = $this -> ci -> config -> item('tls');
        $this -> _base_dn = $this -> ci -> config -> item('base_dn');
        $this -> _ad_domain = $this -> ci -> config -> item('ad_domain');
        $this -> _start_ou = $this -> ci -> config -> item('start_ou');
        $this -> _new_user_ou = $this -> ci -> config -> item('new_user_ou');
        $this -> _shared_mbox_ou = $this -> ci -> config -> item('shared_mbox_ou');
        $this -> _proxy_user = $this -> ci -> config -> item('proxy_user');
        $this -> _proxy_pass = $this -> ci -> config -> item('proxy_pass');
        $this -> _admin_group = $this -> ci -> config -> item('admin_group');

    }

    /**
     * @access public
     * @param string $username
     * @param string $password
     * @return bool Returns true for a correct login and false for an incorrect
     * login
     */
    public function login($username, $password)
    {
        // Initialize encryption
        $this -> init_encryption($username);

        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        if (!$entries = $this -> bind_as_user($username, $password)) {
            // Couldn't bind as the intended user
            $continue = false;
        }

        if ($continue) {
            // bind (i.e. login) for the user was succesful
            log_message(
                'debug',
                'Auth_AD: Successful login for ' . $entries['cn'][0] . '(' . $username . ') from IP ' . $this -> ci -> input -> ip_address()
            );

            // Check if the user is a member of the Domain Admins group
            $is_admin = $this -> in_group($username, $this -> _admin_group);

            // Put useful user data into session
            $user_info = array(
                'cn' => $entries['cn'][0],
                'dn' => stripslashes($entries['dn']),
                'username' => $username,
                'logged_in' => true,
                'objectguid' => $entries['objectguid'][0],
                'is_admin' => $is_admin,
                'p' => $this -> ci -> encryption -> encrypt($password)
            );
            $this -> ci -> session -> set_userdata($user_info);
            // Note: to use the password:
            // $this->[ci->]encryption->decrypt($this->session->userdata('p')

            // set the return marker
            $return = true;
        }

        // return the login result
        return $return;
    }

    /**
     * @access public
     * @return bool
     */
    public function is_authenticated()
    {
        if ($this -> ci -> session -> userdata('logged_in')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @access public
     */
    public function logout()
    {
        log_message('info', 'Auth_AD: User ' . $this -> ci -> session -> userdata('username') . ' logged out.');

        // set the session marker to false (superfluous but safe) and then
        // destroy the session
        $this -> ci -> session -> set_userdata(array('logged_in' => false));
        $this -> ci -> session -> sess_destroy();

    }

    /**
     * @access public
     * @param string $username
     * @param string $groupname
     * @return bool
     */
    public function in_group($username, $groupname)
    {
        // preset the result
        $result = false;

        // preset the continuation marker
        $continue = true;

        // bind to the AD
        if (!$this -> bind_ad()) {
            $continue = false;
        }

        if ($continue) {
            // get the DN for the username
            $user_search = $this -> search_ad($this -> ldap_escape($username, false), array('dn'));
            $user_dn = $user_search['dn'];

            // get the DN for the group
            $group_search = $this -> search_ad($this -> ldap_escape($groupname, false), array('dn'), true);
            $group_dn = $group_search['dn'];

            // search for the user's object
            $attributes = array('memberof');
            $search = ldap_read($this -> _ldap_conn, $user_dn, '(objectclass=*)', $attributes);

            // read the entries
            $entries = ldap_get_entries($this -> _ldap_conn, $search);

            if ($entries['count'] > 0) {
                if (!empty($entries[0]['memberof'])) {
                    for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
                        if ($entries[0]['memberof'][$i] == $group_dn) {
                            $result = true;
                        } elseif ($this -> in_group($entries[0]['memberof'][$i], $groupname)) {
                            $result = true;
                        }
                    }
                }
            }
        }

        // return the result
        return $result;
    }

    /**
     * set_password - use ldap_modify_batch to change a password (unprivileged
     * version for non-administrators)
     *
     * Note: ldap_mod_replace cannot be used by unprivileged users to change
     * their own passwords (results in "insufficient access" error). A remove
     * followed by add is required, passing the original password in the
     * process. ldap_modify_batch is only available to the following PHP
     * versions: PHP 5.4 >= 5.4.26, PHP 5.5 >= 5.5.10, PHP 5.6 >= 5.6.0, PHP 7.
     * On Ubuntu 14.04 this requires the following PPA:
     * https://launchpad.net/~ondrej/+archive/php5 Launchpad logo (for PHP 5.5).
     * For more details, see:
     * http://askubuntu.com/questions/109404/how-do-i-install-latest-php-in-supported-ubuntu-versions-like-5-4-x-in-ubuntu-1
     *
     * @access public
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function set_password($username, $oldPassword, $newPassword)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // are we bound to AD?
        if (!$this -> bind_ad()) {
            $continue = false;
            log_message('error', 'Auth_AD: in set_password(): not logged in');
        }

        if ($continue) {
            // search for the user in AD (we need the DN)
            if (!$entries = $this -> search_ad($username)) {
                $continue = false;
                log_message('error', 'Auth_AD: in modify_user(): cannnot find user');
            }
        }

        if ($continue) {
            // Modify the user on the basis of DN and array of new data; remove
            // old password and add new password
            $dn = $entries['dn'];

            /*
             The following syntax results in this kind of array:

             Array
             (
             [0] => Array
             (
             [attrib] => unicodePwd
             [modtype] => 2
             [values] => Array
             (
             [0] => "oldPassword"
             )

             )

             [1] => Array
             (
             [attrib] => unicodePwd
             [modtype] => 1
             [values] => Array
             (
             [0] => "newPassword"
             )

             )

             )

             */

            $modifs = [
            [
            "attrib" => "unicodePwd",
            "modtype" => LDAP_MODIFY_BATCH_REMOVE,
            "values" => [$this -> encode_password($oldPassword)], ],
            [
            "attrib" => "unicodePwd",
            "modtype" => LDAP_MODIFY_BATCH_ADD,
            "values" => [$this -> encode_password($newPassword)], ], ];
            $result = ldap_modify_batch($this -> _ldap_conn, $dn, $modifs);
        }

        return $result;
    }

    /**
     * @access public
     * @param string $password
     * @return bool
     */
    public function set_own_password($newPassword)
    {
        // pass on to standard set_password() function
        $result = $this -> set_password($this -> ci -> session -> userdata('username'), $this -> ci -> encryption -> decrypt($this -> ci -> session -> userdata('p')), $newPassword);

        // if user's password changed successfully, update the session variable
        if ($result) {
            $user_info = array('p' => $this -> ci -> encryption -> encrypt($newPassword));
            $this -> ci -> session -> set_userdata($user_info);
        }

        // return the result
        return $result;
    }




    /**
     * set_password_su(): password change for any user by domain admin
     *
     * @access public
     * @param string $username (sAMAccountName)
     * @param string $password
     * @return bool
     */
    public function set_password_su($username, $newPassword)
    {

        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        // Admins only
        if (!$this->ci->session->userdata('is_admin')) {
            $continue = false;
        }

        // Get DN of user
        if ($continue) {
            $user = $this -> search_ad($username, array('dn'));
            if(!isset($user['dn'])) {
                prePrint("No such user");
                $continue = false;
            }
        }

        // Set the password
        if ($continue) {
            // ldap_modify throws a warning if the update fails; supress this with @ and handle
            set_error_handler(function($errno, $errstr) {
                log_message('error', "Auth_AD: error no: $errno - $errstr - in set_password_su()");
            }, E_WARNING);
            $result = @ldap_modify(
                $this -> _ldap_conn,
                $user['dn'],
                array(
                    'unicodePwd' => $this->encode_password($newPassword),
                    'physicalDeliveryOfficeName' => 'test text',
                    'UserAccountControl' => '544' // Enabled, password change required
                )
            );
            restore_error_handler();
        }

        // return the result
        return $result;
    }



    /**
     * get_all_user_data(): get lots of information from AD for the named user
     *
     * @access public
     * @param string $username
     * @return bool or array Returns false if fails, or array of data
     */
    public function get_all_user_data($username)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        if ($continue) {
            $return = $this -> search_ad($username, array(
                'agentid',
                'cn',
                'department',
                'displayname',
                'dn',
                'givenname',
                'homemdb',
                //'jpegphoto',
                'lastlogon',
                'lastlogontimestamp',
                'mail',
                'manager',
                'msexcharchivequota',
                'msexchwarnquota',
                'msexchcalendarloggingquota',
                'msexchdumpsterquota',
                'msexchdumpsterwarningquota',
                'msexchrecipientsoftdeletedstatus',
                'objectguid',
                'proxyaddresses',
                'pwdlastset',
                'samaccountname',
                'samaccounttype',
                'sn',
                'sykessshpublickey1',
                'telephonenumber',
                //'thumbnailphoto',
                'title',
                'useraccountcontrol',
                'userprincipalname',
                'whenchanged',
                'whencreated'
            ));

        }
        return $return;
    }

    /**
     * get_user_mail_data(): get mail-related information
     *
     * @access public
     * @param string $username
     * @return bool or array Returns false if fails, or array of mail information
     */
    public function get_user_mail_data($username)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        if ($continue) {
            $results = $this -> search_ad($username, $req_attrs = array(
                'dn',
                'msexchrecipienttypedetails'
            ));
            $dn = $results['dn'];
            // Mailbox type (if any)
            if (isset($results['msexchrecipienttypedetails'][0])) {
                switch ($results['msexchrecipienttypedetails'][0]) {
                    case 1 :
                        $return['mailstatus'] = 'UserMailbox';
                        break;
                    case 64 :
                        $return['mailstatus'] = 'MailContact';
                        break;
                    case 128 :
                        $return['mailstatus'] = 'MailUser';
                        break;
                    default :
                        $return['mailstatus'] = 'Unknown';
                }
            } else {
                $return['mailstatus'] = 'NotEnabled';
            }
        }

        if ($continue && ($return['mailstatus'] != 'NotEnabled')) {
            // 1. Get shared (non-person) mailboxes
            $search = ldap_search($this -> _ldap_conn, $this -> _shared_mbox_ou . ',' . $this -> _base_dn, '(msexchdelegatelistlink=*)',
            // // only look for mailboxes where delegates exist
            array(
                'dn',
                'mail',
                'msexchdelegatelistlink'
            ));
            $mboxes = ldap_get_entries($this -> _ldap_conn, $search);
            foreach ($mboxes as $mbox) {
                // Find out if user has access to this mailbox
                if (isset($mbox['msexchdelegatelistlink'])) {
                    $is_present = array_search($dn, $mbox['msexchdelegatelistlink']);
                    // array_search may return an index of 0, so === comparison
                    // is required
                    if (($is_present !== FALSE) && isset($mbox['mail'][0])) {
                        $return['shared_mboxes'][] = $mbox['mail'][0];
                    }
                }
            }

            // 2. Get details of access to other people's mailboxes
            $search = ldap_search($this -> _ldap_conn, $this -> _start_ou . ',' . $this -> _base_dn, '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msexchdelegatelistlink=*))',
            // // active users only
            array(
                'dn',
                'mail',
                'msexchdelegatelistlink'
            ));
            $mboxes = ldap_get_entries($this -> _ldap_conn, $search);
            foreach ($mboxes as $mbox) {
                // Find out if user has access to this mailbox
                if (isset($mbox['msexchdelegatelistlink'])) {
                    $is_present = array_search($dn, $mbox['msexchdelegatelistlink']);
                    // array_search may return an index of 0, so === comparison
                    // is required
                    if (($is_present !== FALSE) && isset($mbox['mail'][0])) {
                        $return['user_mboxes'][] = $mbox['mail'][0];
                    }
                }
            }

        }
        return $return;
    }

    /**
     * get_user_photos(): ensure user's photos are stored on disk
     *
     * @access public
     * @param string $username
     * @return bool or array Returns false if fails, or array of photo locations
     */
    public function get_user_photos($username)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        if ($continue) {
            $return = $this -> search_ad($username, $req_attrs = array(
                'jpegPhoto',
                'thumbnailPhoto'
            ));
        }
        return $return;
    }

    /**
     * get_all_users(): get list of all AD users
     *
     * @access public
     * @param bool $activeOnly: only users marked active in AD?
     * @return bool or array Returns false if fails, or array of users
     */
    public function get_all_users($activeOnly = TRUE)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        if ($continue) {
            if (strlen($this -> _start_ou) > 0) {
                $search_dn = $this -> _start_ou . ',' . $this -> _base_dn;
            } else {
                $search_dn = $this -> _base_dn;
            }

            $filter = '(&(objectCategory=person)(objectClass=user)' . ($activeOnly ? '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' : '') . ')';

            $req_attrs = array(
                'displayname',
                'dn',
                'mail',
                'department',
                'sn',
                'givenname',
                'samaccountname',
                'description'
            );

            if ($search = ldap_search($this -> _ldap_conn, $search_dn, $filter, $req_attrs)) {
                if (!$return = ldap_get_entries($this -> _ldap_conn, $search)) {
                    log_message('error', 'Auth_AD: in get_all_users() - no users found');
                }
            } else {
                log_message('error', 'Auth_AD: in get_all_users() - could not search');
            }

        }
        return $return;
    }

    /**
     * create_user(): create LDAP user with given parameters
     * We'll just set some basic parameters in this function. Anything more
     * sophisticated can be handled by parameter-setting function calls
     * (on the now-existing user).
     *
     * Note: we truncate sAMAccountName at 20 characters due to problems with Macs, etc.
     */
    public function create_user(
        $username,
        $firstName = '',
        $surname = '',
        $jobTitle = '',
        $phone = '',
        $agentID = '', // For future readers: this is a Sykes-specific custom AD attribute
        $department = '',
        $ou = null
    )
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // Ensure we have a valid LDAP session with the currently logged-on user
        if (!$this -> reauth()) {
            // Uh-oh - couldn't log in with current user
            $continue = false;
        }

        // Admins only
        if (!$this->ci->session->userdata('is_admin')) {
            $continue = false;
        }

        // Create the user
        if ($continue) {
            // Use the default OU to create the user if none presented
            $ou = isset($ou) ? $ou : $this -> _new_user_ou . ',' . $this -> _start_ou . ',' . $this -> _base_dn;

            // ldap_add throws a warning if the add fails; supress this with @ and handle
            set_error_handler(function($errno, $errstr) {
                log_message('error', "Auth_AD: error no: $errno - $errstr - in create_user()");
            }, E_WARNING);

            $return = ldap_add(
                $this -> _ldap_conn,
                'CN=' . $firstName . ' ' . $surname . ',' . $ou,
                array(
                    'sAMAccountName' => substr($username, 0, 20), // Max 20 characters, for compatibility with Macs, etc.
                    'givenName' => $firstName,
                    'sn' => $surname,
                    'title' => $jobTitle,
                    'telephoneNumber' => $phone,
                    'agentid' => $agentID,
                    'department' => $department,
                    'cn' => $firstName . ' ' . $surname,
                    'displayName' => $firstName . ' ' . $surname,
                    'name' => $firstName . ' ' . $surname,
                    'objectclass' => array(
                        'top',
                        'person',
                        'organizationalPerson',
                        'user'
                    ),
                    'UserAccountControl' => '544',
                    'userPrincipalName' => $username . '@' . $this -> _ad_domain
                )
            );
        }
        return $return;
    }

    /**
     * cron_grab(): Run by a cron job to grab attributes for the filter in the
     * given OU
     * Note: since this is run by cron, the only auth is using the proxy user
     * from
     * the config.
     *
     * @access public
     * @param string $ou: The OU to search
     * @return bool or array Returns false if fails, or array of results
     */
    public function cron_grab($req_attrs, $filter, $ou)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // bind to AD
        if (!$this -> bind_ad()) {
            $continue = false;
        }

        if ($continue) {

            if ($search = ldap_search($this -> _ldap_conn, $ou, $filter, $req_attrs)) {
                if (!$return = ldap_get_entries($this -> _ldap_conn, $search)) {
                    log_message('error', 'Auth_AD: in cron_grab() - no results found');
                }
            } else {
                log_message('error', 'Auth_AD: in cron_grab() - could not search');
            }
        }
        return $return;
    }

    /**
     * cron_groups(): Run by a cron job to grab details of all groups under
     * specific OU
     *
     * @access public
     * @param string $ou: The OU to search
     * @return bool or array Returns false if fails, or array of groups
     */
    public function cron_groups($ou)
    {
        $filter = '(objectCategory=group)';
        $req_attrs = array(
            'objectguid',
            'cn',
            'description',
            'dn',
            'grouptype',
            'whencreated',
            'whenchanged'
        );
        return $this -> cron_grab($req_attrs, $filter, $ou);
    }

    /**
     * cron_users(): Run by a cron job to grab details of all users under
     * specific OU
     *
     * @access public
     * @param string $ou: The OU to search
     * @return bool or array Returns false if fails, or array of users
     */
    public function cron_users($ou)
    {
        $filter = '(&(objectCategory=person)(objectClass=user))';
        $req_attrs = array(
            'objectguid',
            'agentid',
            'cn',
            'department',
            'dn',
            'givenname',
            'homemdb',
            'instancetype',
            'mail',
            'manager',
            'msexcharchivequota',
            'msexcharchivewarnquota',
            'msexchrecipientdisplaytype',
            'msexchrecipienttypedetails',
            'proxyaddresses',
            'samaccountname',
            'samaccounttype',
            'sn',
            'sykessshpublickey1',
            'telephonenumber',
            'title',
            'useraccountcontrol',
            'whencreated',
            'whenchanged'
        );
        return $this -> cron_grab($req_attrs, $filter, $ou);
    }

    /**
     * bind_as_user(): connect to AD with the specified credentials
     *
     * @access private
     * @param string $username
     * @param string $password
     * @return bool or array Returns false if fails, or array of basic LDAP
     * details
     */
    private function bind_as_user($username, $password)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // check for non-empty parameters
        if (strlen($username) > 0 && strlen($password) > 0) {
            // First, bind to AD using the standard user (from the config)
            if (!$this -> bind_ad()) {
                $continue = false;
            }

            if ($continue) {
                // Look for the specified user in AD (using the standard user
                // from the config)
                if (!$return = $this -> search_ad($username, array(
                    'dn',
                    'cn',
                    'objectguid'
                ))) {
                    // User doesn't exist!
                    $continue = false;
                }
            }

            if ($continue) {
                /*
                 Now we have an LDAP session properly configured and we know the
                 specified user exists, attempt to bind again as this user.
                 Note: don't want any LDAP error message to appear - handle that
                in the app
                 */
                if (!$bind = @ldap_bind($this -> _ldap_conn, stripslashes($return['dn']), $password)) {
                    log_message('debug', 'Auth_AD: Unable to log in the user.');
                    $return = false;
                }
            }
        }
        return $return;
    }

    /**
     * reauth(): ensure we're logged in (prior to performing LDAP operations)
     *
     * NOTE: ONLY USE IF USER DATA IS ALREADY IN SESSION
     * This is required, since we may have logged in using a different instance
     * of the Auth_AD object, in a different controller, hence this object will
     * not have a valid LDAP connection. We use the details of the previously
     * logged-in user from session data to log in again. This ensures the LDAP
     * connection is ready for subsequent operations, using the correct
     * credentials
     * (of the currently logged-in user).
     *
     * @access private
     * @return bool Returns false if fails; array of username, password otherwise
     */
    private function reauth()
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        if (!$this -> is_authenticated()) {
            // We've not previously logged in; that's not what this function is
            // for
            $continue = false;
        }

        if ($continue) {
            // Grab username from session data - if it's missing, something's
            // wrong
            $username = $this -> ci -> session -> userdata('username');

            // initialize encryption (since we need access to user's password)
            $this -> init_encryption($username);
            $password = $this -> ci -> encryption -> decrypt($this -> ci -> session -> userdata('p'));

            // We need the username, password and a successful rebind
            if (isset($username) && isset($password) && $this -> bind_as_user($username, $password)) {
                $return = true;
            }
        }

        return $return;
    }

    /**
     * encode_password(): convert password to unicode
     *
     * This is required because AD passwords are stored in unicode format.
     * Specifically, when
     * setting, the password needs to be enclosed with double quotes and encoded
     * in UTF-16LE.
     *
     * @access private
     * @param string $password
     * @return string
     */
    private function encode_password($password)
    {
        return iconv("UTF-8", "UTF-16LE", '"' . $password . '"');
    }

    /**
     * modify_user(): make changes to AD user
     *
     * @access private
     * @param string $username
     * @param array $newData
     * @return bool or int Returns false if fails, or integer error code
     */
    private function modify_user($username, $newData)
    {
        // preset the return marker
        $return = false;

        // preset the process step marker
        $continue = true;

        // are we bound to AD?
        if (!$this -> bind_ad()) {
            $continue = false;
            log_message('error', 'Auth_AD: in modify_user(): not logged in');
        }

        if ($continue) {
            // search for the user in AD (we need the DN)
            if (!$entries = $this -> search_ad($username)) {
                $continue = false;
                log_message('error', 'Auth_AD: in modify_user(): cannnot find user');
            }
        }

        if ($continue) {
            // TODO: Complete this
            // Modify the user on the basis of DN and array of new data
            $dn = $entries['dn'];
            echo "<pre>In modify_user: \n";
            print_r($this -> _ldap_conn);
            print_r($dn);
            print_r($newData);
            echo "</pre>";
            $result = ldap_mod_replace($this -> _ldap_conn, "CN=Rob Test,OU=Testing,OU=Sykes New Domain,DC=sykescottages,DC=co,DC=uk", $newData);
            //$result = ldap_mod_replace($this->_ldap_conn, $dn,
            // array($newData));

        }

        return $result;
    }

    /**
     * @access private
     * @param string $account
     * @param array $req_attrs
     * @param bool $from_root; whether or not to perform a search from the AD
     * root (default = false)
     * @return bool or array
     */
    private function search_ad($account, $req_attrs = array('dn', 'cn'), $from_root = false)
    {
        // preset the result
        $result = array();

        // set up the search parameters
        //(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))
        $filter = '(sAMAccountName=' . $this -> ldap_escape($account, false) . ')';
        if ($from_root) {
            $search_dn = $this -> _base_dn;
        } elseif (strlen($this -> _start_ou) > 0) {
            $search_dn = $this -> _start_ou . ',' . $this -> _base_dn;
        } else {
            $search_dn = $this -> _base_dn;
        }

        // perform the search for the username
        if ($search = ldap_search($this -> _ldap_conn, $search_dn, $filter, $req_attrs)) {
            if ($entries = ldap_get_entries($this -> _ldap_conn, $search)) {
                if ($entries['count'] > 0) {
                    foreach ($req_attrs as $key => $val) {
                        // Using @ since we don't need a NOTICE if the index
                        // doesn't exist
                        $result[$val] = @$entries[0][$val];
                    }
                }
            } else {
                log_message('error', 'Auth_AD: Unable to get entries for account.');
                show_error('Unable to read the AD entries for the account');
            }
        } else {
            log_message('error', 'Auth_AD: Unable to perform search for the account.');
            show_error('Unable to search the AD for the account.');
        }

        // return the result
        if (count($result) == count($req_attrs)) {
            return $result;
        } else {
            return false;
        }
    }

    /**
     * @access private
     * @return bool
     */
    private function bind_ad()
    {
        // preset the continuation marker
        $continue = true;

        // attempt to connect to each of the AD servers, stop if a connection is
        // succesful
        foreach ($this->_hosts as $host) {
            $this -> _ldap_conn = ldap_connect($host);
            if ($this -> _ldap_conn) {
                break;
            } else {
                log_message('info', 'Auth_AD: Error connecting to AD server ' . $host);
            }
        }

        // check for an active LDAP connection
        if (!$this -> _ldap_conn) {
            log_message('error', "Auth_AD: unable to connect to any AD servers.");
            show_error('Error connecting to any Active Directory server(s). Please check your configuration and connections.');
            $continue = false;
        }

        if ($continue) {
            // set some required LDAP options
            ldap_set_option($this -> _ldap_conn, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($this -> _ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

            // attempt to bind to the AD using the proxy user or anonymously if
            // no user was configured
            if ($this -> _proxy_user != null) {
                $bind = ldap_bind($this -> _ldap_conn, $this -> _proxy_user, $this -> _proxy_pass);
            } else {
                $bind = ldap_bind($this -> _ldap_conn);
            }

            // verify the LDAP binding
            if (!$bind) {
                if ($this -> _proxy_user != null) {
                    log_message('error', 'Auth_AD: Unable to perform LDAP bind using user ' . $this -> _proxy_user);
                    show_error('Unable to bind (i.e. login) to the AD for user ID lookup');
                } else {
                    log_message('error', 'Auth_AD: Unable to perform anonymous LDAP bind.');
                    show_error('Unable to bind (i.e. login) to the AD for user ID lookup');
                }
                $continue = false;
            } else {
                log_message('debug', 'Auth_AD: Successfully bound to AD. Performing DN lookup for user');
            }
        }

        // Start TLS if required by config
        if ($continue && $this -> _tls) {
            // Options required for TLS
            ldap_set_option($this -> _ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($this -> _ldap_conn, LDAP_OPT_REFERRALS, 0);

            // initiate TLS connection
            if (!ldap_start_tls($this -> _ldap_conn)) {
                log_message('debug', 'Auth_AD: Could not start TLS session.');
                $continue = false;
            } else {
                log_message('debug', 'Auth_AD: TLS session started.');
            }
        }

        // return the result
        return $continue;
    }

    /**
     * @access private
     * @param string $str
     * @param bool $for_dn
     * @return string
     */
    private function ldap_escape($str, $for_dn = false)
    {
        /**
         * This is courtesy of douglass_davis at earthlink dot net
         * Posted in comments at
         * http://php.net/manual/en/function.ldap-search.php on 2009/04/08
         *
         * see:
         * RFC2254
         * http://msdn.microsoft.com/en-us/library/ms675768(VS.85).aspx
         * http://www-03.ibm.com/systems/i/software/ldap/underdn.html
         */

        if ($for_dn) {
            $metaChars = array(
                ',',
                '=',
                '+',
                '<',
                '>',
                ';',
                '\\',
                '"',
                '#'
            );
        } else {
            $metaChars = array(
                '*',
                '(',
                ')',
                '\\',
                chr(0)
            );
        }

        $quotedMetaChars = array();
        foreach ($metaChars as $key => $value) {
            $quotedMetaChars[$key] = '\\' . str_pad(dechex(ord($value)), 2, '0');
        }

        $str = str_replace($metaChars, $quotedMetaChars, $str);
        return $str;
    }

    /**
     * init_encryption(): set up encryption, 'salted' with username
     *
     * @access private
     * @param string $username
     */
    private function init_encryption($username)
    {
        /*
         * The only way for users to reset their own passwords is in a batch
         * that includes the old password. Therefore we need to encrypt and
         * store the password for later use. Bad Rob.
         *
         * To make this a little *less bad*, let's "salt" the encryption key
         *  with the username.
         *
         * And yes, cryptography isn't a strength of mine, so anyone feel free
         * to make this better!
         */
        $key = $this -> ci -> config -> item('encryption_key');
        $this -> ci -> encryption -> initialize(array('key' => $username . $key));
    }

}

/* End of file Auth_AD.php */
/* Location: ./application/libraries/Auth_AD.php */
