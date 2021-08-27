<?php

$host = "https://api.mastersindia.co";
$requestUrl=array(
    'access_token'=>$host.'/oauth/access_token',
    'host'=>$host 
);
define ("requestUrl", serialize ($requestUrl));

//Sample user data information to get access_token
$accessTokenInfo=array(    
    'username' =>'apiiso@mastersindia.co',
    'password' =>'Eway@123#',
    'client_id' =>'2HkHiaXfPdNRTNwxaCASbplGNpiJSLkB',
    'client_secret' =>'I0FJ6lHO7pjTLqpcbwzyaORKJr5kht38',
    'grant_type' =>'password',
);
define ("accessTokenInfo", serialize ($accessTokenInfo));

//Einvoice GSTIN information 
$einvGstinInfo=array(      
    'gstin' =>'',
    'einvUsername' =>'',
    'einvPassword' =>'',
    
);

define ("einvGstinInfo", serialize ($einvGstinInfo));




?>




