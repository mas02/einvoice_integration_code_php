<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include_once 'constants.php';
include_once 'Security.php';

class common {

    /**
     * getRandomCode Method
     * 
     * @param $length
     * @param $type
     * @return string
     */
    public function getRandomCode($length, $type = null) {
        // Random characters
        if ($type == 'alphabetic') {
            $keys = array_merge(range('a', 'z'), range('A', 'Z'));
        } elseif ($type == 'numeric') {
            $characters = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
            $keys = array_merge(range(0, 9));
        } else {
            $keys = array_merge(range(0, 9), range('a', 'z'), range('A', 'Z'));
        }
        // set the array
        $key = '';
        for ($i = 0; $i < $length; $i++) {
            $key .= $keys[array_rand($keys)];
        }
        // display random key
        return $key;
    }

    /**
     * Function used to encrypt data with GSP app-key
     * @param string $data
     * @param type $appKey
     * @return string
     */
    public function EncryptWithAppKey($data, $appKey) {
        $iv = $appKey; // pass app-key as $iv
        $blocksize = 16;
        $pad = $blocksize - (strlen($data) % $blocksize);
        $data = $data . str_repeat(chr($pad), $pad);
        return bin2hex(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $appKey, $data, MCRYPT_MODE_CBC, $iv));
    }

    /**
     * Encrypt App-key with GSP public key
     */
    public function encryptAspPubliKey($data) {
        $fp = fopen(__dir__ . "/files/server.crt", "r");
        $public = fread($fp, 8192);
        fclose($fp);
        openssl_public_encrypt($data, $encryptedData, $public, OPENSSL_PKCS1_PADDING);
        // Return encrypted app-key
        return base64_encode($encryptedData);
    }
    
    /**
     * This method used to encrypt data with EK
     *
     */
    public function encryptData($value, $ek) {
        $key = base64_decode($ek);
        $response['error'] = false;
        $response['data'] = Security::encrypt($value, $key);

        return $response;
    }
    
    /**
     * decryptData Method
     * @param string $data
     * @param string $appkey
     * @return string
     */
    public function decryptData($data, $appkey) {
        $value = $data;
        $key = base64_decode($appkey); //16 Character Key
        return Security::decrypt($value, $key);
    }

    /**
     * getAccessToken method
     * 
     * Method used to get access-token from GSP(Masters India)
     * @param type $JsonAspUser
     * @param type $appKey
     * @return string
     */
    public function getAccessToken() {
        
        //fetch GSP user data
        $aspUserInfo = unserialize(accessTokenInfo);
        $aspUserData['username'] = $aspUserInfo['username'];
        $aspUserData['password'] = $aspUserInfo['password'];
        $aspUserData['client_id'] = $aspUserInfo['client_id'];
        $aspUserData['client_secret'] = $aspUserInfo['client_secret'];
        $aspUserData['grant_type'] = $aspUserInfo['grant_type'];
        $JsonAspUser = json_encode($aspUserData);
        //generate app-key of 16 character length
        $appKey = $this->getRandomCode(16);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($JsonAspUser, $appKey);
        //encrypt app-key with Public key
        $encryptedWithPub = $this->encryptAspPubliKey($appKey);
        if ($encryptedWithPub) {
            //prepare data for access token
            $EncryptedData['credentials_data'] = $encryptedWithAppKey;
            $EncryptedData['app_key'] = $encryptedWithPub;
            $HeaderOption = array('Content-Type: application/json');
            $json_encode_data = json_encode($EncryptedData);
            //send request to get access token
            $GSPApiUrl = unserialize(requestUrl);
            $url = $GSPApiUrl['access_token'];
            $result = $this->sendGSPRequest($url, $json_encode_data, 'POST');
            if (isset($result) && isset($result->accessToken)) {
                $response['error'] = false;
                $response['access_token'] = $result->accessToken;
                $response['expire'] = $result->expires_in;
                $response['app_key'] = $appKey;
            } else{
                if (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error)) {
                        $msg = $result->error->error_description->error_description;
                    }elseif(isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    } else {
                        $msg = $result->error_description;
                    }
                }else{
                    $msg = "Service not available. Please, try after sometime";
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Error in encrypting with public key';
        }

        return $response;
    }
    




     /**
     * eInvEncryption method
     * Method used to encrypt app key for E-Inv API
     * @param string $pass
     * @access public
     * @return string
     */
    public function eInvEncryption($pass = null) {
        

        if ($pass != null || $pass != '') {
            $appKey = base64_encode($pass);
            
        } else {
            $appKey = base64_encode($this->getRandomCode(32));
        }
        
        //read Einv pem file        
        $fp = fopen(__dir__."/PublicKey/Einv_publickey.pem", "r");
        
        $pub_key = fread($fp, 8192);
        
        fclose($fp);
        //encrypt app key with Einv public key
        
        openssl_public_encrypt(base64_decode($appKey), $crypttext, $pub_key);
       
        $res = base64_encode($crypttext);
        
        $response['flat_app_key'] = $appKey;
        $response['encrypt_app_key'] = $res;
        //print_r($response);
        return $response;
    }
    
    /**
     * EinvApiAuthenticate method
     * method used to authenticate TP from E-Inv system
     * @return array
     */
    public function EinvApiAuthenticate($EinvUsername,$EinvPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin) {        
       
        $other_param_data['access_token'] = $access_token;
//            if ($redirect_url != null) {
//                $other_param_data['uri'] = $redirect_url;
//            }
        $other_param_json = json_encode($other_param_data);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
        $app_key_data = $this->eInvEncryption();
             
        $reqData['UserName'] = $EinvUsername;
        $reqData['Password'] = $EinvPassword;
        $reqData['AppKey'] = $app_key_data['flat_app_key'];
        $reqData['ForceRefreshAccessToken'] = false;
	    $encryptReqData=$this->eInvEncryption(base64_encode(json_encode($reqData)));
        
	    
        $fields['Data']= $encryptReqData['encrypt_app_key'];
        $fields['other_parameters'] = $encryptedWithAppKey;
        $data = json_encode($fields);
        $GstrApiUrl = unserialize(requestUrl);
        $url = $GstrApiUrl['host'].'/eivital/v1.04/auth';
        //send user's header
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['Gstin'] = $gstin;
        $encodedOtherDetails = json_encode($otherDetail);
        $result = $this->sendGSPRequest($url, $data, 'POST', $encodedOtherDetails);
            
        if ($result) {
            if (isset($result->Status) && $result->Status == 1) {
                //decrypt sek with app key
                $sek = $result->Data->Sek; //temp
                $ek = $this->decryptData($sek, $app_key_data['flat_app_key']);
                if ($ek) {
                    $response['error'] = false;
                    $response['einv_sek'] = $result->Data->Sek;
                    $response['einv_auth_token'] = $result->Data->AuthToken;
                    $response['einv_expiry'] = isset($result->Data->expiry) ? $result->data->expiry : 360;
                    $response['einv_tokan_expiry'] = date('Y-m-d H:i:s',strtotime($result->Data->TokenExpiry));
                    //$response['einv_ek'] = $ek;
                    $response['einv_app_key'] = $app_key_data['flat_app_key'];
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Error in decrypting sek in E-inv'; //temp
                }
            } else {
                if (isset($result->Status) && $result->Status == 0) {
                    if(is_array($result->ErrorDetails)){
                        $msg='';
                        $i=1;
                        foreach($result->ErrorDetails as $val){
                            if($i==1){
                                $errorCode =$val->ErrorCode;
                                $msg .= "$val->ErrorCode: $val->ErrorMessage";
                            }else{
                                $msg .= "$val->ErrorCode: $val->ErrorMessage, ";
                            }
                            $i++;
                        }
                    }
                    
                }else if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                }elseif (isset($result->Message)) {
                    $msg = $result->Message;
                }elseif (isset($result->error)) {
                    $msg = $result->error;
                } else {
                    $msg = 'There seems to be too much load on NIC server, please try after sometime';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'There seems to be too much load on NIC server, please try after sometime';
        }
        return $response;
    }
    
   
    /**
     * saveEwayData method
     * Method used to save data to the E-Way system
     * 
     * @param string $data_json (Request JSON Payload)
     * @param string $action
     * @param string $gstin
     * @param string $einv_auth_token
     * @param string $einv_app_key
     * @param string $einv_sek
     * @param string $access_token
     * @param string $ASP_client_id
     * @param string $ASP_app_key
     * @return array
     */
    public function saveEinvData($data_json, $action,$einv_username,$gstin,$einv_auth_token,$einv_app_key,$einv_sek,$access_token,$ASP_client_id,$ASP_app_key) {
        if($action == 'Cancel'){
           echo "<br><br><br><strong>Cancel IRN</strong><br><br><br>"; 
        }else{
            echo "<br><br><br><strong>Generate IRN</strong><br><br><br>";
        } 
               
        $auth_token=$einv_auth_token;
        $flat_app_key=$einv_app_key;
        $sek=$einv_sek;

        $other_param_data['access_token'] = $access_token;       
        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
            
        //get $ek
        $ek = $this->decryptData($sek, $flat_app_key);
      
        //encrypt data with EK
        $enc = $this->encryptData($data_json, base64_encode($ek));

        if (!isset($enc['data'])) {
            $response['error'] = true;
            $response['message'] = "Invalid ek";
            return $response;
        }
        
        $fields['Data'] = $enc['data']; //base64 encoded data
        $fields['other_parameters'] = $encryptedWithAppKey;
        $data = json_encode($fields);
        $GstrApiUrl = unserialize(requestUrl);
        if($action == 'Cancel'){
            $url = $GstrApiUrl['host'].'/eicore/v1.03/Invoice/Cancel';
        }else{
            $url = $GstrApiUrl['host'].'/eicore/v1.03/Invoice';
        }
        
        $method = 'POST';
        //send user's header
        $otherDetail['AuthToken'] = $auth_token;
        $otherDetail['user_name'] = $einv_username;
        $otherDetail['Gstin'] = $gstin;
        $otherDetail['client-id'] = $ASP_client_id;
        
        $encodedOtherDetails = json_encode($otherDetail);
        
        //send data to GST System
        $result = $this->sendGSPRequest($url, $data, $method, $encodedOtherDetails);
        if (isset($result->Status) && $result->Status == 1) {
            $encodedData = $this->decryptData($result->Data, base64_encode($ek));
            $response['error'] = false;
            $response['data'] = $encodedData;
            $response['reqData'] = base64_encode($data_json);
        } else {
            if (isset($result->Status) && $result->Status == 0) {
                if(is_array($result->ErrorDetails)){
                    $msg='';
                    $i=1;
                    foreach($result->ErrorDetails as $val){
                        if($i==1){
                            $errorCode =$val->ErrorCode;
                            $msg .= "$val->ErrorCode: $val->ErrorMessage";
                        }else{
                            $msg .= "$val->ErrorCode: $val->ErrorMessage, ";
                        }
                        $i++;
                    }
                }

            }elseif (isset($result->error->message)) {
                $msg = $result->error->message;
            } elseif (isset($result->error->desc)) {
                $msg = $result->error->desc;
            } elseif (isset($result->message)) {
                $msg = $result->message;
            } elseif (isset($result->error_msg)) {
                $msg = $result->error_msg;
            } elseif (isset($result->error->error_cd)) {
                if (isset($result->error->error_description->error_description)) {
                    $msg = $result->error->error_description->error_description;
                } elseif (isset($result->error->error_description)) {
                    $msg = $result->error->error_description;
                }
            }elseif (isset($result->Message)) {
                $msg = $result->Message;
            }elseif (isset($result->error)) {
                $msg = $result->error;
            } else {
                $msg = 'There seems to be too much load on NIC server, please try after sometime';
            }
            $response['error'] = true;
            $response['message'] = $msg;
        }
        return $response;
    }
    /**
     * getEinvData method
     * Method used to get data from E-Way system
     *
     */
    public function getEinvData($IRN_No,$action,$einv_username,$gstin,$einv_username,$einv_auth_token,$einv_app_key,$einv_sek,$access_token,$ASP_client_id,$ASP_app_key) {
        
        $auth_token=$einv_auth_token;
        $flat_app_key=$einv_app_key;
        $sek=$einv_sek;        
        $other_param_data['access_token'] = $access_token;
       
        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
       
        //get $ek
        $ek = $this->decryptData($sek, $flat_app_key);
        
        $response['error']=false;
        $GstrApiUrl = unserialize(requestUrl);
        $url = $GstrApiUrl['host'];
        if($action=='irn'){
             if(isset($IRN_No) && $IRN_No!=''){
                $url .= '/eicore/v1.03/Invoice/irn/'.$IRN_No;
            }else{
                $response['error']=true;
                $response['message']='irn_no is missing in request';
            }
        }else{
            $response['error']=true;
            $response['message']='Wrong action in request';
        }
        //send user's header
        $otherDetail['AuthToken'] = $auth_token;
        $otherDetail['user_name'] = $einv_username;
        $otherDetail['Gstin'] = $gstin;
        $otherDetail['client-id'] = $ASP_client_id;
        $encodedOtherDetails = json_encode($otherDetail);
        
        //send data to GST System
        
        $url .= '?other_parameters=' . $encryptedWithAppKey;

        
        if($response['error']==false){
        $result = $this->sendGSPRequest($url, $data=null, $method=null, $encodedOtherDetails);
        
       
        if (isset($result->Status) && $result->Status == 1) {
            $encodedData = $this->decryptData($result->Data, base64_encode($ek));
            $response['error'] = false;
            $response['data'] = $encodedData;
        } else {
            if (isset($result->Status) && $result->Status == 0) {
                if(is_array($result->ErrorDetails)){
                    $msg='';
                    $i=1;
                    foreach($result->ErrorDetails as $val){
                        if($i==1){
                            $errorCode =$val->ErrorCode;
                            $msg .= "$val->ErrorCode: $val->ErrorMessage";
                        }else{
                            $msg .= "$val->ErrorCode: $val->ErrorMessage, ";
                        }
                        $i++;
                    }
                }

            }elseif (isset($result->error->message)) {
                $msg = $result->error->message;
            } elseif (isset($result->error->desc)) {
                $msg = $result->error->desc;
            } elseif (isset($result->message)) {
                $msg = $result->message;
            } elseif (isset($result->error_msg)) {
                $msg = $result->error_msg;
            } elseif (isset($result->error->error_cd)) {
                if (isset($result->error->error_description->error_description)) {
                    $msg = $result->error->error_description->error_description;
                } elseif (isset($result->error->error_description)) {
                    $msg = $result->error->error_description;
                }
            }elseif (isset($result->Message)) {
                $msg = $result->Message;
            }elseif (isset($result->error)) {
                $msg = $result->error;
            } else {
                $msg = 'There seems to be too much load on NIC server, please try after sometime';
            }
            $response['error'] = true;
            $response['message'] = $msg;
        }
        return $response;
    }
    }

    /**
     * send request
     */
    function sendGSPRequest($url, $data = null, $method = null, $other_detail_json = null) {
        $HeaderOption = array('Content-Type: application/json');
        if ($other_detail_json != null) {
            $other_detail = json_decode($other_detail_json, true);
            foreach ($other_detail as $key => $value) {
                array_push($HeaderOption, $key . ':' . $value);
            }
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
       
        curl_setopt($ch, CURLOPT_HTTPHEADER, $HeaderOption);
        if ($method == 'POST' || $method == 'PUT') {
            if ($method == 'PUT') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            } else {
                curl_setopt($ch, CURLOPT_POST, 1);
            }
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, fopen('php://stderr', 'w'));
        // Execute post
        $result = curl_exec($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err = curl_error($ch);
        curl_close($ch);
        $result2 = json_decode($result);

        return $result2;
    }

}
