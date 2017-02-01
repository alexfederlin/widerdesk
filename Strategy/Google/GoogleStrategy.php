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
        'redirect_uri'  => '{complete_url_to_strategy}int_callback',
        #'scope'         => 'trust'
    );

    /**
     * Auth request
     */
    public function request(){
        $url = 'api.nextgen-lab.net:20006/uaa/oauth/token';
        $params = array(
            'client_id' => $this->strategy['client_id']#,
            #'redirect_uri' => $this->strategy['redirect_uri']
        );

        if (!empty($this->strategy['scope'])) $params['scope'] = $this->strategy['scope'];
        if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];
        if (!empty($this->strategy['response_type'])) $params['response_type'] = $this->strategy['response_type'];
        if (!empty($this->strategy['display'])) $params['display'] = $this->strategy['display'];
        if (!empty($this->strategy['auth_type'])) $params['auth_type'] = $this->strategy['auth_type'];

        $this->clientGet($url, $params);
    }

    /**
     * Internal callback, after Emergency's OAuth
     */
    public function int_callback(){
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
            #$url = 'https://graph.facebook.com/oauth/access_token';
            $url = 'api.nextgen-lab.net:20006/uaa/oauth/token';
            $params = array(
                'client_id' =>$this->strategy['app_id'],
                'client_secret' => $this->strategy['app_secret'],
                'redirect_uri'=> $this->strategy['redirect_uri'],
                'code' => trim($_GET['code'])
            );
            $response = $this->serverGet($url, $params, null, $headers);

            parse_str($response, $results);

            if (!empty($results) && !empty($results['access_token'])){
                $me = $this->me($results['access_token']);

                $this->auth = array(
                    'provider' => 'Emergency',
                    'uid' => $me->id,
                    'info' => array(
                        'name' => $me->name,
                        'image' => 'https://graph.facebook.com/'.$me->id.'/picture?type=square'
                    ),
                    'credentials' => array(
                        'token' => $results['access_token'],
                        'expires' => date('c', time() + $results['expires'])
                    ),
                    'raw' => $me
                );

                if (!empty($me->email)) $this->auth['info']['email'] = $me->email;
                if (!empty($me->username)) $this->auth['info']['nickname'] = $me->username;
                if (!empty($me->first_name)) $this->auth['info']['first_name'] = $me->first_name;
                if (!empty($me->last_name)) $this->auth['info']['last_name'] = $me->last_name;
                if (!empty($me->location)) $this->auth['info']['location'] = $me->location->name;
                if (!empty($me->link)) $this->auth['info']['urls']['facebook'] = $me->link;
                if (!empty($me->website)) $this->auth['info']['urls']['website'] = $me->website;
                if (!empty($me->gender)) $this->auth['info']['gender'] = $me->gender;
                if (!empty($me->locale)) $this->auth['info']['locale'] = $me->locale;
                if (!empty($me->timezone)) $this->auth['info']['timezone'] = $me->timezone;

                /**
                 * Missing optional info values
                 * - description
                 * - phone: not accessible via Emergency Graph API
                 */

                $this->callback();
            }
            else{
                $error = array(
                    'provider' => 'Emergency',
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => $headers
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