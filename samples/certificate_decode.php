<?php

require '../src/WebSSL.class.php';
require '../src/Certificate.class.php';
$webSSL = new WebSSL("https://c1.cloudhsms.com");

$fileUserCert = 'John2.crt';

$certificatePem = file_get_contents($fileUserCert);

$certificateArray = $webSSL->x509DecodeCertificate($certificatePem);

$certificate = new Certificate($certificateArray);

echo '<pre>' . $certificate->toString(). '<pre>';

?>