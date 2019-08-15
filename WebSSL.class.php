<?php
/**
 * 	PHP class for WebSSL
 *	WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.
 */
 
class WebSSL {

	 /**
	 * Send curl request and return
	 */
	
	function send($url, array $jsonData) {
		
		//Initiate cURL.
		$ch = curl_init($url);
		
		//Encode the array into JSON.
		$jsonDataEncoded = json_encode($jsonData, JSON_UNESCAPED_SLASHES);
		 
		//Tell cURL that we want to send a POST request.
		curl_setopt($ch, CURLOPT_POST, 1);
		 
		//Attach our encoded JSON string to the POST fields.
		curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonDataEncoded);
		 
		//Set the content type to application/json
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json')); 
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		 
		//Execute the request
		$result = curl_exec($ch);
		
		//Decode the JSON array
		$resultDecode = json_decode($result, true);

		return $resultDecode;
	}
	
	 /**
	 * Generates a cryptographic key pair inside a HSM. The private key is AES encrypted by a HSM and returned in a 
	 * PEM encoded encrypted private key structure. * The public key is returned PEM encoded.
	 *
	 * $algorithm -- Type: String Required: yes Description: Algorithms (rsa-2048, rsa-4096, ecc-p256, rsa-p521).
	 */
	 
	function genpkeyGenerateKey($algorithm) {
		
		$url = "https://c1.cloudhsms.com/genpkey";
		 
		//The JSON data.
		$jsonData = array(
			'algorithm' => $algorithm
		);
		
		$resultDecode = $this->send($url, $jsonData);
		 
		$privateKey = $resultDecode['privateKey'];
		$publicKey = $resultDecode['publicKey'];
		
		return array($privateKey,$publicKey);
	}
	
	 /**
	 * Signs a Certifcate Signing Request (CSR) in the HSM and composes an x509 certificate.
	 *
	 * $days -- Type: String Required: yes Description: The number of days the certificate will be valid for.
	 * $digest -- Type: String Required: yes Description: CSR digest (sha-256)
	 * $csr -- Type: String Required: yes Description: Certificate Signing Request (PEM encoded)
	 * $signerCert -- Type: String Required: yes Description: Signers x509 certficate (PEM encoded)
	 * $inKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 */
	 
	function x509SignCSR($days,$digest,$csr,$signerCert,$inKey) {
		
		$url = "https://c1.cloudhsms.com/x509/signCsr";
		 
		//The JSON data.
		$jsonData = array(
			'days' => $days,
			'digest' => $digest,
			'csr' => $csr,
			'signerCert' => $signerCert,
			'inKey' => $inKey
			
		);
		 
		$output = str_replace(array("\r\n", "\n", "\r", "\\"),'',$jsonData);

		$resultDecode = $this->send($url, $output);
		
		$certificate = $resultDecode['certificate'];
		
		error_log($certificate);
		
		return $certificate;
	}
	
	 /**
	 * Generates a PKCS#10 Certificate Signing Request (CSR) within the HSM, by signing the applicants 
	 * distinguished name fields with their private key.
	 *
	 * $inKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 * $csrDigest -- Type: String Required: yes Description: CSR digest (sha-256)
	 * $dn -- Type: object Required: yes Description: CSR Distinguished names
	 */
	 
	function reqGenerateCSR($inKey, $csrDigest, $dn) {
		
		$url = "https://c1.cloudhsms.com/req/generateCsr";
		 
		//The JSON data.
		$jsonData = array(
		
			'inKey' => $inKey,
			'digest' => $csrDigest,
			'distinguishedNames' => $dn
			
		);
		 
		$resultDecode = $this->send($url, $jsonData);
		 
		$csr = $resultDecode['csr'];

		return $csr;

	}
	
	/**
	 * Generates a key pair within the HSM and self signed certificate.
	 *
	 * $algorithm -- Type: String Required: yes Description: Algorithms (rsa-2048, rsa-4096, ecc-p256, ecc-p521).
	 * $certDays -- Type: String Required: yes Description: The number of days the certificate will be valid for.
	 * $csrDigest -- Type: object Required: yes Description: CSR digest (sha-256)
	 * $certSubjectType -- Type String Required: yes Description: Certificate subject type (CA, End Entity)
	 * $dn -- Type: object Required: yes Description: CSR Distinguished names
	 */
	 
	function reqGenKeyCert($algorithm, $certDays, $csrDigest, $certSubjectType, $dn) {
		
		$url = "https://c1.cloudhsms.com/req/generateKeyCert";
		 
		//The JSON data.
		$jsonData = array(
			'algorithm' => $algorithm,
			'days' => $certDays,
			'digest' => $csrDigest,
			'subjectType' => $certSubjectType,
			'distinguishedNames' => $dn
		);
		 
		$resultDecode = $this->send($url, $jsonData);
		 
		$privateKey = $resultDecode['privateKey'];
		$certificate = $resultDecode['certificate'];
		

		return array($privateKey,$certificate);

	}
	
	/**
	 * Signs data within a HSM as CMS signed-data content, using the signers encrypted private key and certificate.
	 *
	 * $data -- Type: String Required: yes Description: Data to sign (Base64 encoded)
	 * $signersKey -- Type: String Required: yes Description: Signers key (PEM encoded encrypted private key)
	 * $signerCert -- Type: object Required: yes Description: Signers Certificate (PEM encoded certificate)
	 */
	 
	function cmsSign($data, $signersKey , $signerCert) {
		
		//Initiate cURL.
		$url = "https://c1.cloudhsms.com/cms/sign";
		 
		//The JSON data.
		$jsonData = array(
			'inKey' => $signersKey,
			'signer' => $signerCert,
			'in' => base64_encode($data)
		);
		 
		$resultDecode = $this->send($url, $jsonData);
		 
		$cms = $resultDecode['cms'];
		
		//Remove BEGIN CMS
		$searchBEGIN = '-----BEGIN CMS-----' ;
		$resultTrimBEGIN = str_replace($searchBEGIN, '', $cms);
		
		//Remove END CMS
		$searchEND = '-----END CMS-----' ;
		$resultTrimEND = str_replace($searchEND, '', $resultTrimBEGIN);
		
		return  $resultTrimEND;
		
	}
}

?>
