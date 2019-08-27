<?php
/**
 * 	PHP class for creating a Public Key Infrastructure
 *	WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.
 */

require '../src/WebSSL.class.php';
$webSSL = new WebSSL("https://c1.cloudhsms.com");

$fileCaCert = 'ca_test.crt';
$fileCaKey = 'ca_test.key';
$fileUserCert = 'user_test.crt';
$fileUserKey = 'user_test.key';

$userP12Password = "test";
$userCertDays = "365";

// Setup CA certificate parameters
$caDN = array (
	'commonName' => "AdamCA",
	'country' => "UK",
	'state' => "West Sussex",
	'locality' => "Littlehampton",
	'organisation' => "Microexpert",
	'organisationalUnit' => "Mx",
	'email' => "info@microexpert.co.uk"
);

$caKeyUsage = array (
	"CRLSign",
	"dataEncipherment",
	"digitalSignature",
	"keyAgreement",
	"keyCertSign",
	"keyEncipherment",
	"nonRepudiation"
);

$caEnhancedKeyUsage = array ();

$caBasicContraints = array (
	"subjectType" => "CA",
	"pathLengthConstraint" => "1"
);



// Setup user certificate parameters
$userDN = $caDN;
$userDN['commonName'] = 'User';
$userDN['email'] = 'user@demo.com';

$userEnhancedKeyUsage = array (
	"clientAuthentication",
	"emailProtection"
);

$userBasicContraints = array (
	"subjectType" => "End Entity"
);

// Using the values set in enchanced key usage determine what should be set in the standard key usage 
function determineKeyUsage(array $enhancedKeyUsage) {
	$keyUsage = array();

	if(in_array('clientAuthentication', $enhancedKeyUsage)) {
		array_push($keyUsage, "digitalSignature");
		array_push($keyUsage, "keyEncipherment");
		array_push($keyUsage, "keyAgreement");
	}

	if(in_array('serverAuthentication', $enhancedKeyUsage)) {
		array_push($keyUsage, "digitalSignature");
		array_push($keyUsage, "keyAgreement");
	}

	if(in_array("emailProtection", $enhancedKeyUsage)) {
		array_push($keyUsage, "digitalSignature");
		array_push($keyUsage, "nonRepudiation");
		array_push($keyUsage, "keyEncipherment");
		array_push($keyUsage, "keyAgreement");
	}

	if(in_array("timeStamping", $enhancedKeyUsage)) {
		array_push($keyUsage, "digitalSignature");
		array_push($keyUsage, "nonRepudiation");
	}

	if(in_array("codeSigning", $enhancedKeyUsage)) {
		array_push($keyUsage, "digitalSignature");
	}

	return array_values(array_unique($keyUsage));
}


// Check if CA certificate and key exist.
if(!file_exists($fileCaCert ) || !file_exists($fileCaKey)) {
	error_log("Unable to find either CA Certificate or CA key files.");

	// Generate Key and Self Signed Certificate and key
 	$caKeyAndCert = $webSSL->reqGenKeyCert('365', $caDN, $caKeyUsage, $caEnhancedKeyUsage, $caBasicContraints);

 	$caKeyAndCert['privateKey'];
 	$caKeyAndCert['certificate'];

 	// Write to files
	file_put_contents($fileCaCert, $caKeyAndCert['privateKey']);
	file_put_contents($fileCaKey, $caKeyAndCert['certificate']);
}

$caCert = file_get_contents($fileCaCert);
$caKey = file_get_contents($fileCaKey);

// Create User Key, Certificate and return P12 file. 
$userP12 = $webSSL->reqGenerateKeyAndSignedCertificate($userP12Password, $caCert, $caKey,
		$userCertDays, $userDN, determineKeyUsage($userEnhancedKeyUsage), $userEnhancedKeyUsage, $userBasicContraints);

header('Content-Type: application/x-pkcs12');
header('Content-Disposition: attachment; filename="user.p12"');
echo base64_decode($userP12);

?>
