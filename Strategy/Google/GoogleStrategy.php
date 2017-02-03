<?php
/**
 * Google strategy for Opauth
 * based on https://developers.facebook.com/docs/authentication/server-side/
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.GoogleStrategy
 * @license      MIT License
 */

class GoogleStrategy extends OpauthStrategy{

    /**
     * Compulsory config keys, listed as unassociative arrays
     * eg. array('app_id', 'app_secret');
     */
    public $expects = array('client_id', 'client_secret');

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri'  => '{complete_url_to_strategy}oauth2callback',
        'scope'         => 'trust'
    );

    /**
     * Auth request
     */
    public function request(){
        $url = 'api.nextgen-lab.net:20006/uaa/oauth/authorize';
        $params = array(
            'client_id' => $this->strategy['client_id'],
            'response_type' => 'code'
            #'redirect_uri' => $this->strategy['redirect_uri']
        );


        $this->clientGet($url, $params);
    }

    /**
     * Internal callback, after Emergency's OAuth
     */
    public function oauth2callback(){
	
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
            $url = 'ericsson:ericssonsecret@api.nextgen-lab.net:20006/uaa/oauth/token';
            $params = array(
                'code' => trim($_GET['code']),
		'grant_type' => 'authorization_code'
            );
            #$response = $this->serverPost($url, $params, null, $headers);
            $response = $this->sendCurlPost($url, $params);
	 
	    $results = json_decode($response);
	        $fp = fopen('/tmp/results.log', 'w');
		$res = print_r($results,true);
		fwrite($fp, "Res:");
		fwrite($fp, $res);
    
	    if (!empty($results) && !empty($results->access_token)){
	        $token = $results->access_token;    
		$userinfo = $this->userinfo($token);


		$fp = fopen('/tmp/newuserinfo.log', 'w');
		$user = print_r($userinfo,true);
		fwrite($fp, "Userinfo:");
		fwrite($fp, $user);
		fclose($fp);
		$this->auth = array(
	        		    'uid' => $userinfo['uid'],
	        		    'info' => array(),
	        		    'credentials' => array(
	        			    'token' => $results->access_token,
	        			    'expires' => date('c', time() + $results->expires_in)
	        			    ),
	        		    'raw' => $userinfo
	        		    );

	        if (!empty($results->refresh_token))
	        {
	           $this->auth['credentials']['refresh_token'] = $results->refresh_token;
	        }

	        $this->mapProfile($userinfo, 'primaryMail', 'info.email');
	        $this->mapProfile($userinfo, 'firstname', 'info.first_name');
	        $this->mapProfile($userinfo, 'lastname', 'info.last_name');
	    #   $this->mapProfile($userinfo, 'picture', 'info.image');

		$this->callback();
	    }

	    else{
	            $error = array(
	        		    'code' => 'access_token_error',
	        		    'message' => 'Failed when attempting to obtain access token',
	        		    'raw' => array(
	        			    'response' => $response,
	        			    'headers' => $headers
	        			    )
	        		  );

	            $this->errorCallback($error);
	    }   

	}
	else{
		$error = array(
				'provider' => 'Emergency',
				'code' => $_GET['error'],
				'message' => $_GET['error_description'],
				'raw' => $_GET
            );

            $this->errorCallback($error);
        }
    }


    private function sendCurlPost($url, $fields)
    {
	    //url-ify the data for the POST
	    $fields_string = '';
	    foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
	    rtrim($fields_string, '&');

	    //open connection
	    $ch = curl_init();

	    //set the url, number of POST vars, POST data
	    curl_setopt($ch,CURLOPT_URL, $url);
	    curl_setopt($ch,CURLOPT_POST, count($fields));
	    curl_setopt($ch,CURLOPT_POSTFIELDS, $fields_string);
	    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

	    //execute post
	    $result = curl_exec($ch);

	    //close connection
	    curl_close($ch);


	    return $result;
    }

    private function sendCurlGet($url, $fields, $headers)
    {
	    //url-ify the data for the POST
	    $fields_string = '';
	    foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
	    rtrim($fields_string, '&');

	    //open connection
	    $ch = curl_init();

	    //set the url, number of POST vars, POST data
	    curl_setopt($ch,CURLOPT_URL, $url);
	    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

	    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	    //execute post
	    $result = curl_exec($ch);

	    //close connection
	    curl_close($ch);


	    return $result;
    }

    /**
     * Queries Emergency API for user info
     *
     * @param string $access_token 
     * @return array Parsed JSON results
     */
    private function userinfo($access_token){
	    $headers = array(
	        	    'Authorization' => 'Authorization: Bearer' . ' ' . $access_token
	        	    );
	    $params = array();

	    $userinfo = $this->sendCurlGet('api.nextgen-lab.net:20006/uaa/user2', $params, $headers);
	    

	    if (!empty($userinfo)){
	            return $this->recursiveGetObjectVars(json_decode($userinfo));
	    }
	    else{
	            $error = array(
	        		    'code' => 'userinfo_error',
	        		    'message' => 'Failed when attempting to query for user information',
	        		    'raw' => array(
	        			    'response' => $userinfo,
	        			    'headers' => $headers
	        			    )
	        		  );

	            $this->errorCallback($error);
	    }
    }
    /**
     * Queries Emergency Graph API for user info
     *
     * @param string $access_token 
     * @return array Parsed JSON results
     */
    private function me($access_token){
        $me = $this->serverGet('https://graph.facebook.com/me', 
            array('access_token' => $access_token,
             'fields' => 'id,name,first_name,last_name,email,locale,timezone,gender'
            ),
            null, $headers);
        if (!empty($me)){
            return json_decode($me);
        }
        else{
            $error = array(
                'provider' => 'Emergency',
                'code' => 'me_error',
                'message' => 'Failed when attempting to query for user information',
                'raw' => array(
                    'response' => $me,
                    'headers' => $headers
                )
            );

            $this->errorCallback($error);
        }
    }
}
