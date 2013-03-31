<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
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
 * @package         Auth_AD
 * @subpackage      configuration
 * @author          Mark Kathmann <mark@stackedbits.com>
 * @version         0.3
 * @link            http://www.stackedbits.com/
 * @license         GNU Lesser General Public License (LGPL)
 * @copyright       Copyright © 2013 Mark Kathmann <mark@stackedbits.com>
 */

// hosts: an array of AD servers (usually domain controllers) to use for authentication		
$config['hosts'] = array('mydc01.mydomain.local', 'mydc02.mydomain.local');

// ports: an array containing the remote port number to connect to (default is 389) 
$config['ports'] = array(389);

// base_dn: the base DN of your Active Directory domain
$config['base_dn'] = 'DC=mydomain,DC=local';

// ad_domain: the domain name to prepend (versions prior to Windows 2000) or append (Windows 2000 and up)
$config['ad_domain'] = 'mydomain.local';

// start_ou: the DN of the OU you want to start searching from. Leave empty to start from domain root.
// examples: 'OU=Users' or 'OU=Corporate,OU=Users'
$config['start_ou'] = '';

// proxy_user: the (distinguished) username of the user that does the querying (AD generally does not allow anonymous binds) 
$config['proxy_user'] = 'MyUser@mydomain.local';

// proxy pass: the password for the proxy_user
$config['proxy_pass'] = 'myPassword';

/* End of file auth_ad.php */
/* Location: ./application/config/auth_ad.php */
