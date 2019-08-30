<?php

require '../src/WebSSL.class.php';
require '../src/CSR.class.php';
$webSSL = new WebSSL("https://c1.cloudhsms.com");

$fileUserCsr = 'test.csr';

$csrPem = file_get_contents($fileUserCsr);

$csrArray = $webSSL->reqDecodeCSR($csrPem);

$csr = new CSR($csrArray);

echo '<pre>' . $csr->toString(). '<pre>';

?>