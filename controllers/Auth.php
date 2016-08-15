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
 * @package         Auth_AD
 * @subpackage      example
 * @author          Mark Kathmann <mark@stackedbits.com>
 * @version         0.4
 * @link            http://www.stackedbits.com/
 * @license         GNU Lesser General Public License (LGPL)
 * @copyright       Copyright © 2013 Mark Kathmann <mark@stackedbits.com>
 */

class Auth extends CI_Controller 
{
	function __construct() 
	{
		parent::__construct();
		
		// this loads the Auth_AD library. You can also choose to autoload it (see config/autoload.php)
		$this->load->library('Auth_AD');
	}
	
	public function login()
	{
		// read the form fields, lowercase the username for neatness
		$username = strtolower($this->input->post('username'));
		$password = $this->input->post('password');
		
		// check the login
		if($this->auth_ad->login($username, $password))
		{			
			// the login was succesful, do your thing here
			// upon a succesful login the session will automagically contain some handy user data:
			// $this->session->userdata('cn') contains the common name from the AD
			// $this->session->userdata('username') contains the username as processed
			// $this->session->userdata('dn') contains the distinguished name from the AD
			// $this->session->userdata('logged_in') contains a boolean (true)
		}
		else
		{
			// user could not be authenticated, whoops.
		}
	}
	
	public function logout()
	{
		// perform the logout
		if($this->session->userdata('logged_in')) 
		{
			$data['name'] = $this->session->userdata('cn');
			$data['username'] = $this->session->userdata('username');
			$data['logged_in'] = true;
			$this->auth_ad->logout();
		} 
		else 
		{
			$data['logged_in'] = false;
		}
		
		// now that the logout is done, you can add code for the next step(s) here
	}
	
	public function checkloginstatus()
	{
		// check if the user is already logged in
		if(!$this->auth_ad->is_authenticated())
		{
			// not logged in, do what you need to do here
			// you could, for example, send the user to the login form
		}
		else 
		{
			// already logged in, forward to the home page or some such
		}
	}
	
	public function useringroup()
	{
		// check if the user is a member of a particular group (recursive search)
		if ($this->auth_ad->in_group($username, $groupname))
		{
			// the user is a member of the group
		}
		else 
		{
			// nope, not a member
		}
	}
}