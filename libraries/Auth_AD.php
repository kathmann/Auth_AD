<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/*
 * This file is part of Auth_AD.

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
 * 
 */
 
/**
 * Auth_AD Class
 *
 * Simple Active Directory LDAP authentication library for Code Igniter.
 *
 * @package         Auth_AD
 * @author          Mark Kathmann <mark@stackedbits.com>
 * @version         0.4
 * @link            http://www.stackedbits.com/
 * @license         GNU Lesser General Public License (LGPL)
 * @copyright       Copyright © 2013 Mark Kathmann <mark@stackedbits.com>
 */

class Auth_AD 
{
	// register properties
	private $_hosts;
	private $_ports;
	private $_base_dn;
	private $_ad_domain;
	private $_start_ou;
	private $_proxy_user;
	private $_proxy_pass;
	private $_ldap_conn;
	
	/**
     * @access public
     */
	function __construct() 
	{
		// start the first initialisation
		$this->ci =& get_instance();
		log_message('debug', 'Auth_AD initialising');
	
		// load the configuration file
		$this->ci->load->config('auth_ad');
		
		// load the session library
		$this->ci->load->library('session');
		
		// perform the secondary initialisation
		$this->_init();
	}

	/**
     * @access private
     */
	private function _init() 
	{
		// check for an active LDAP extension
		if (!function_exists('ldap_connect')) 
		{
			log_message('error', 'Auth_AD: LDAP PHP module not found.');
			show_error('LDAP PHP module not found. Please ensure that the module is loaded or compiled in.');
		}
		
		// register the configuration variables as properties
		$this->_hosts      = $this->ci->config->item('hosts');
		$this->_ports      = $this->ci->config->item('ports');
		$this->_base_dn    = $this->ci->config->item('base_dn');
		$this->_ad_domain  = $this->ci->config->item('ad_domain');
		$this->_start_ou   = $this->ci->config->item('start_ou');
		$this->_proxy_user = $this->ci->config->item('proxy_user');
		$this->_proxy_pass = $this->ci->config->item('proxy_pass');
	}

	/**
     * @access public
     * @param string $username
     * @param string $password
     * @return bool Returns true for a correct login and false for an incorrect login
     */
	function login($username, $password) 
	{
		// preset the return marker
		$return = false;
		
		// preset the process step marker
		$continue = true;
		
		// check for non-empty parameters
		if (strlen($username) > 0 && strlen($password) > 0)
		{
			// bind to the AD
			if (!$this->bind_ad())
			{
				$continue = false;
			}
			
			if ($continue)
			{
				// search for the user in the AD
				if (!$entries = $this->search_ad($username, array('dn', 'cn')))
				{
					$continue = false;
				}
			}
			
			if ($continue)
			{
				// attempt to bind as the requested user
				if (!$bind = ldap_bind($this->_ldap_conn, stripslashes($entries['dn']), $password)) 
				{
            		log_message('debug', 'Auth_AD: Unable to log in the user.');
					$continue = false;
				}
				else 
				{
					// bind (i.e. login) for the user was succesful, read the user attributes
					$cn = $entries['cn'][0];
					$dn = stripslashes($entries['dn']);
					
					log_message('debug', 'Auth_AD: Successful login for user ' . $cn . ' (' . $username . ') from IP ' . $this->ci->input->ip_address());
					
					// set the session data for the user
					$user_info = array('cn' => $cn, 'dn' => $dn, 'username' => $username, 'logged_in' => true);
					$this->ci->session->set_userdata($user_info);
					
					// set the return marker
					$return = true;
				}
			}
		}
		
		// return the login result
		return $return;
	}
	
	/**
	* @access public
	* @return bool
	*/
	function is_authenticated() 
	{
		if ($this->ci->session->userdata('logged_in')) 
		{
			return true;
		} 
		else 
		{
			return false;
		}
	}
    
	/**
	* @access public
	*/
	function logout() 
	{
		log_message('info', 'Auth_AD: User ' . $this->ci->session->userdata('username') . ' logged out.');
		
		// set the session marker to false (superfluous but safe) and then destroy the session
		$this->ci->session->set_userdata(array('logged_in' => false));
		$this->ci->session->sess_destroy();
	}
	
	/**
	* @access public
	* @param string $user_dn
	* @param string $groupname
	* @return bool
	*/
	function in_group($username, $groupname)
	{
		// preset the result
		$result = false;
		
		// preset the continuation marker
		$continue = true;
		
		// bind to the AD
		if (!$this->bind_ad())
		{
			$continue = false;
		}
		
		if ($continue)
		{
			// get the DN for the username
			$user_search = $this->search_ad($this->ldap_escape($username, false), array('dn'));
			$user_dn     = $user_search['dn'];
			
			// get the DN for the group
			$group_search = $this->search_ad($this->ldap_escape($groupname, false), array('dn'));
			$group_dn     = $group_search['dn'];
			
			// search for the user's object
			$attributes = array('memberof');
			$search = ldap_read($this->_ldap_conn, $user_dn, '(objectclass=*)', $attributes);
			
			// read the entries
			$entries = ldap_get_entries($this->_ldap_conn, $search);
			
			if ($entries['count'] > 0) 
			{
				if (!empty($entries[0]['memberof'])) 
				{
					for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) 
					{
						if ($entries[0]['memberof'][$i] == $group_dn) 
						{
							$result = true;
						}
						elseif ($this->in_group($entries[0]['memberof'][$i], $groupname)) 
						{ 
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
	* @access private
	* @param string $account
	* @param array $req_attrs
	* @return bool or array
	*/
	private function search_ad($account, $req_attrs = array('dn', 'cn'))
	{
		// preset the result
		$result = array();
		
		// set up the search parameters
		$filter  = '(sAMAccountName=' . $this->ldap_escape($account, false) . ')';
		if (strlen($this->_start_ou) > 0)
		{
			$search_dn = $this->_start_ou . ',' . $this->_base_dn;
		}
		else 
		{
			$search_dn = $this->_base_dn;
		}
		
		// perform the search for the username
		if ($search = ldap_search($this->_ldap_conn, $search_dn, $filter, $req_attrs))
		{
			if ($entries = ldap_get_entries($this->_ldap_conn, $search))
			{
				if ($entries['count'] > 0)
				{
					foreach ($req_attrs as $key => $val)
					{
						$result[$val] = $entries[0][$val];
					}
				}
			}
			else 
			{
				log_message('error', 'Auth_AD: Unable to get entries for account.');
				show_error('Unable to read the AD entries for the account');
			}
		}
		else 
		{
			log_message('error', 'Auth_AD: Unable to perform search for the account.');
			show_error('Unable to search the AD for the account.');
		}
		
		// return the result
		if (count($result) == count($req_attrs))
		{
			return $result;
		}
		else 
		{
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
		
		// attempt to connect to each of the AD servers, stop if a connection is succesful 
		foreach ($this->_hosts as $host) 
		{
			$this->_ldap_conn = ldap_connect($host);
			if ($this->_ldap_conn) 
			{
				break;
			}
			else 
			{
				log_message('info', 'Auth_AD: Error connecting to AD server ' . $host);
			}
		}
		
		// check for an active LDAP connection
		if (!$this->_ldap_conn) 
		{
			log_message('error', "Auth_AD: unable to connect to any AD servers.");
			show_error('Error connecting to any Active Directory server(s). Please check your configuration and connections.');
			$continue = false;
		}
		
		if ($continue)
		{
			// set some required LDAP options		
			ldap_set_option($this->_ldap_conn, LDAP_OPT_REFERRALS, 0);
			ldap_set_option($this->_ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		
			// attempt to bind to the AD using the proxy user or anonymously if no user was configured
			if ($this->_proxy_user != null)
			{
				$bind = ldap_bind($this->_ldap_conn, $this->_proxy_user, $this->_proxy_pass);
			}
			else 
			{
				$bind = ldap_bind($this->_ldap_conn);
			}
			
			// verify the LDAP binding
			if (!$bind)
			{
				if ($this->_proxy_user != null)
				{
					log_message('error', 'Auth_AD: Unable to perform LDAP bind using user ' . $this->_proxy_user);
					show_error('Unable to bind (i.e. login) to the AD for user ID lookup');
				}
				else
				{
					log_message('error', 'Auth_AD: Unable to perform anonymous LDAP bind.');
					show_error('Unable to bind (i.e. login) to the AD for user ID lookup');
				}
				$continue = false;
			}
			else 
			{
				log_message('debug', 'Auth_AD: Successfully bound to AD. Performing DN lookup for user');
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
		* This function courtesy of douglass_davis at earthlink dot net
		* Posted in comments at
		* http://php.net/manual/en/function.ldap-search.php on 2009/04/08
		*
		* see:
		* RFC2254
		* http://msdn.microsoft.com/en-us/library/ms675768(VS.85).aspx
		* http://www-03.ibm.com/systems/i/software/ldap/underdn.html
		*/  
		
		if ($for_dn)
		{
			$metaChars = array(',','=', '+', '<','>',';', '\\', '"', '#');
		}
		else
		{
			$metaChars = array('*', '(', ')', '\\', chr(0));
		}
		
		$quotedMetaChars = array();
		foreach ($metaChars as $key => $value) 
		{
			$quotedMetaChars[$key] = '\\' . str_pad(dechex(ord($value)), 2, '0');
		}
		
		$str = str_replace($metaChars, $quotedMetaChars, $str);
		return $str;  
	}
}

/* End of file Auth_AD.php */
/* Location: ./application/libraries/Auth_AD.php */
