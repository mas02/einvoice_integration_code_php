<?php

include_once './libs/common.php';

//accessToken();
// einvAuthToken();
//generateIrn();
//getIrn();
cancelIrn();


function accessToken(){
	$common = new common();
	$resp = $common->getAccessToken();
	echo "<br><br><strong>Response</strong><br><br>";
	echo '<pre>';
	print_r($resp);
}

function einvAuthToken(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$einvGstinInfo = unserialize(einvGstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$respponseAccessToken = $common->getAccessToken();
	echo "<br><br><strong>Access Token Response From Masters India</strong><br><br>";
	echo '<pre>';
	print_r($respponseAccessToken);

	$gstin=$einvGstinInfo['gstin'];//Einv GSTIN
	$EinvUsername=$einvGstinInfo['einvUsername'];
	$EinvPassword=$einvGstinInfo['einvPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EinvApiAuthenticate($EinvUsername,$EinvPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);
	echo "<br><br><strong>AuthToken Response</strong><br><br>";
	print_r($responseAuthToken);

}


function generateIrn(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$einvGstinInfo = unserialize(einvGstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$respponseAccessToken = $common->getAccessToken();


	$gstin=$einvGstinInfo['gstin'];//Einv GSTIN
	$einv_username =$EinvUsername=$einvGstinInfo['einvUsername'];
	$EinvPassword=$einvGstinInfo['einvPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EinvApiAuthenticate($EinvUsername,$EinvPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);

	//Recevied in authentication_from_nic.php
	$einv_auth_token=$responseAuthToken['einv_auth_token'];
	//Recevied in authentication_from_nic.php
	$einv_app_key=$responseAuthToken['einv_app_key'];
	//Recevied in authentication_from_nic.php
	$einv_sek=$responseAuthToken['einv_sek'];

	$no = $common->getRandomCode(5);
	$docNo = 'Test/'.$no;
	//Get Authtoken from Einv System
	$json_data = '{"Version":"1.1","TranDtls":{"TaxSch":"GST","SupTyp":"B2B","RegRev":"N","IgstOnIntra":"N"},"DocDtls":{"Typ":"INV","No":"'.$docNo.'","Dt":"08\/03\/2021"},"SellerDtls":{"Gstin":"09AAAPG7885R002","LglNm":"Colorshine Coated Private Limi","TrdNm":"Colorshine Coated Private Limi","Addr1":"1229 - 1, 1230 -2Chennuru Bit - 1 villageGuduru Mandal","Addr2":"1229 - 1, 1230 -2Chennuru Bit - 1 villageGuduru Mandal","Loc":"Manesar","Pin":201301,"Stcd":"09","Ph":"9100090540","Em":"corporate@colorshine.net"},"BuyerDtls":{"Gstin":"05AAAPG7885R002","LglNm":"Century Wells Roofing India Pv","TrdNm":"Century Wells Roofing India Pv","Addr1":"No 219A, Bommasandra Industrial AreaSurvey No 19( Part) 35 And 36Bommasadra Villege Attibele Hobli,","Loc":"Gurgaon","Pin":263001,"Pos":"05","Stcd":"05"},"DispDtls":{"Nm":"Century Wells Roofing India Pv","Addr1":"No 219A, Bommasandra Industrial AreaSurvey No 19( Part) 35 And 36Bommasadra Villege Attibele Hobli,","Loc":"Manesar","Pin":122050,"Stcd":"06"},"ShipDtls":{"Gstin":"06AAACA7205Q1ZK","LglNm":"Colorshine Coated Private Limi","TrdNm":"Colorshine Coated Private Limi","Addr1":"1229 - 1, 1230 -2Chennuru Bit - 1 villageGuduru Mandal","Loc":"Gurgaon","Pin":122001,"Stcd":"06"},"ValDtls":{"AssVal":613258.68,"CgstVal":0,"SgstVal":0,"IgstVal":110386.56,"CesVal":0,"StCesVal":0,"Discount":0,"OthChrg":0,"RndOffAmt":0,"TotInvVal":723645.24,"TotInvValFc":12897.7},"ItemList":[{"SlNo":"1","PrdDesc":"COLORSHINE PRATHAM PPGI COIL","IsServc":"N","HsnCd":"721011","Barcde":"123456","Qty":4.015,"Unit":"MTS","UnitPrice":77194,"TotAmt":309933.91,"Discount":0,"PreTaxVal":0,"AssAmt":309933.91,"GstRt":18,"IgstAmt":55788.1,"CgstAmt":0,"SgstAmt":0,"CesRt":0,"CesAmt":0,"CesNonAdvlAmt":0,"StateCesRt":0,"StateCesAmt":0,"StateCesNonAdvlAmt":0,"OthChrg":0,"TotItemVal":365722.01},{"SlNo":"2","PrdDesc":"COLORSHINE PRATHAM PPGI COIL","IsServc":"N","HsnCd":"721011","Barcde":"123456","Qty":3.955,"Unit":"MTS","UnitPrice":76694,"TotAmt":303324.77,"Discount":0,"PreTaxVal":0,"AssAmt":303324.77,"GstRt":18,"IgstAmt":54598.46,"CgstAmt":0,"SgstAmt":0,"CesRt":0,"CesAmt":0,"CesNonAdvlAmt":0,"StateCesRt":0,"StateCesAmt":0,"StateCesNonAdvlAmt":0,"OthChrg":0,"TotItemVal":357923.23}]}';
	$action='Invoice';
	$responseAuthToken = $common->saveEinvData($json_data, $action,$einv_username,$gstin,$einv_auth_token,$einv_app_key,$einv_sek,$access_token,$ASP_client_id,$ASP_app_key);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($responseAuthToken);
}

function getIrn(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$einvGstinInfo = unserialize(einvGstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$respponseAccessToken = $common->getAccessToken();


	$gstin=$einvGstinInfo['gstin'];//Einv GSTIN
	$einv_username =$EinvUsername=$einvGstinInfo['einvUsername'];
	$EinvPassword=$einvGstinInfo['einvPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EinvApiAuthenticate($EinvUsername,$EinvPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);

	//Recevied in authentication_from_nic.php
	$einv_auth_token=$responseAuthToken['einv_auth_token'];
	//Recevied in authentication_from_nic.php
	$einv_app_key=$responseAuthToken['einv_app_key'];
	//Recevied in authentication_from_nic.php
	$einv_sek=$responseAuthToken['einv_sek'];

	$IRN_No='07add7ad1c4412de66b0c58f4562edce52dd449bc05bbc02dff8f2a0a3b509d2';
	$action='irn';
	$responseAuthToken = $common->getEinvData($IRN_No,$action,$einv_username,$gstin,$einv_username,$einv_auth_token,$einv_app_key,$einv_sek,$access_token,$ASP_client_id,$ASP_app_key);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($responseAuthToken);

}

function cancelIrn(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$einvGstinInfo = unserialize(einvGstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$respponseAccessToken = $common->getAccessToken();


	$gstin=$einvGstinInfo['gstin'];//Einv GSTIN
	$einv_username =$EinvUsername=$einvGstinInfo['einvUsername'];
	$EinvPassword=$einvGstinInfo['einvPassword'];
	$access_token=$respponseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$respponseAccessToken['app_key'];
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//Get Authtoken from Eway System
	$responseAuthToken = $common->EinvApiAuthenticate($EinvUsername,$EinvPassword,$gstin,$access_token,$ASP_client_id,$ASP_app_key,$gstin);

	//Recevied in authentication_from_nic.php
	$einv_auth_token=$responseAuthToken['einv_auth_token'];
	//Recevied in authentication_from_nic.php
	$einv_app_key=$responseAuthToken['einv_app_key'];
	//Recevied in authentication_from_nic.php
	$einv_sek=$responseAuthToken['einv_sek'];
	$IRN_No = '07add7ad1c4412de66b0c58f4562edce52dd449bc05bbc02dff8f2a0a3b509d2';
	//Get Authtoken from Einv System
	$json_data = '{"Irn":"'.$IRN_No.'","CnlRsn":"1","CnlRem":"Wrong entry"}';
	$action='Cancel';
	$responseAuthToken = $common->saveEinvData($json_data, $action,$einv_username,$gstin,$einv_auth_token,$einv_app_key,$einv_sek,$access_token,$ASP_client_id,$ASP_app_key);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($responseAuthToken);

}



?>