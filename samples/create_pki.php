<?php
/**
 * 	PHP class for creating a Public Key Infrastructure
 *	WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.
 */

require '../src/WebSSL.php';
$webSSL = new WebSSL(true);

$fileCa = 'ca_test.crt';
$fileCert = 'user_test.crt';
$fileKey = 'user_test.key';

/**
 * CA and User CSR Distinguished names
 */
 
$caDN = array (
	'commonName' => "AdamCA",
	'country' => "UK",
	'state' => "West Sussex",
	'locality' => "Littlehampton",
	'organisation' => "Microexpert",
	'organisationalUnit' => "Mx",
	'email' => "info@microexpert.co.uk"
);
	
$userDN = array (
	'commonName' => "Adam",
	'country' => "UK",
	'state' => "West Sussex",
	'locality' => "Littlehampton",
	'organisation' => "Microexpert",
	'organisationalUnit' => "Mx",
	'email' => "info@microexpert.co.uk"
);

/**
 * Generate Key and Self Signed Certificate : Generates a key pair within the HSM and self 
 * signed certificate.
 */
 
$keyCert = $webSSL->reqGenKeyCert('rsa-2048','365','sha-256','CA',$caDN);

$caPrivateKey = $keyCert[0];
$caCertificate = $keyCert[1];

/**
 * Generate Key : Generates a cryptographic key pair inside a HSM. The private key is AES encrypted by 
 * a HSM and returned in a PEM encoded encrypted private key structure. The public key is returned PEM
 * encoded. rsa-4096, ecc-p521 are restricted to users with WebSSL credentials (TLS client certificate and key).
 */
 
$userKeys = $webSSL->genpkeyGenerateKey('rsa-2048');

$userPrivateKey = $userKeys[0];
$userPublicKey = $userKeys[1];

/**
 * Generate CSR : Generates a PKCS#10 Certificate Signing Request (CSR) within the HSM, by signing the applicants
 * distinguished name fields with their private key. 
 */
 
$userCSR = $webSSL->reqGenerateCSR($userPrivateKey,'sha-256',$userDN);

/**
 * Sign CSR : Signs a Certifcate Signing Request (CSR) in the HSM and composes an x509 certificate.
 */
 
$userCert = $webSSL->x509SignCSR('365', 'sha-256', $userCSR, $caCertificate, $caPrivateKey);

$current = file_get_contents($fileCa);
file_put_contents($fileCa, $caCertificate);

$current = file_get_contents($fileCert);
file_put_contents($fileCert, $userCert);

$current = file_get_contents($fileKey);
file_put_contents($fileKey, $userPrivateKey);


?>
