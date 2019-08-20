<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require '../PHPMailer/Exception.php';
require '../PHPMailer/PHPMailer.php';
require '../PHPMailer/SMTP.php';
require 'WebSSL.class.php';

assert_options(ASSERT_ACTIVE, 1);


/**
 * SecurePHPMailer class
 * 
 * This class extends the functionality of PHPMailer's PHPMailer class.
 * @see       https://github.com/PHPMailer/PHPMailer/ - The PHPMailer GitHub project.
 * 
 * The extended class provides S/MIME signed an encrypted emailing functionality. 
 * SecurePHPMailer utilises a remote Hardware-Secure-Module (HSM)
 * @see       https://www.webssl.io - The HTTP HSM
 *
 */
class SecurePHPMailer extends PHPMailer
{
	private $webSSL;
	private $sendersCertificate;
	private $sendersEncryptedKey;

	/**
	 * SecurePHPMailer Constructor
	 *
	 * @param 	string 	$sendersCertPath 	The file path to a PEM encoded X.509 Certificate file
	 * @param 	string 	$sendersKeyPath 	The file path to a PEM encoded Encrypted/Plain PKCS#8 key file. 
	 * @return 	object 
	 */
	public function __construct($sendersCertPath, $sendersKeyPath) 
	{
		$this->webSSL = new WebSSL();
		$this->sendersCertificate = file_get_contents($sendersCertPath, FILE_USE_INCLUDE_PATH);
		$this->sendersKey = file_get_contents($sendersKeyPath, FILE_USE_INCLUDE_PATH);
		parent::__construct();
    	}

	private function composeSignedEmail()
	{
		// Create new MIME boundary
		$boundary = $this->generateId();

		// Split original email 
		$emailParts = explode("MIME-Version: 1.0\r\n", $this->getSentMimeMessage(), 2);
		if (count($emailParts) != 2) throw new Exception("Unable to split Email Header from Footer.");

		// Compose new SMIME Header
		$this->MIMEHeader = $emailParts[0] .
			"MIME-Version: 1.0\r\n" .
			'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; boundary="----'. $boundary . '"\r\n\r\n';

		// Send email body to WebSSL.io. Returns PKCS#7/CMS SignedData 
		$cms = $this->webSSL->cmsSign($emailParts[1], $this->sendersKey, $this->sendersCertificate);

		// Compose new SMIME Body
		$this->MIMEBody = 
			"This is an S/MIME signed message\r\n\r\n" .
			"------$boundary\r\n" . 
			$emailParts[1] . "\r\n" . 
			"------$boundary\r\n" .
			"Content-Type: application/pkcs7-signature; name='smime.p7s'\r\n" . 
			"Content-Transfer-Encoding: base64\r\n" .
			"Content-Disposition: attachment; filename='smime.p7s'\r\n" .
			"Content-Description: S/MIME Cryptographic Signature\r\n" .
			$cms . "\r\n" .
			"------$boundary--\r\n";
	}

	private function composeEncryptedEmail($recipientCertPath)
	{
		// Open PEM Certificate 
		$recipientCertificate = file_get_contents($recipientCertPath, FILE_USE_INCLUDE_PATH);
		
		// Split original email 
		$emailParts = explode("MIME-Version: 1.0\r\n", $this->getSentMimeMessage());
		if (count($emailParts) != 2) throw new Exception("Unable to split Email Header from Footer.");

		// Compose new SMIME Header
		$this->MIMEHeader = $emailParts[0] .
			"MIME-Version: 1.0\r\n" .
			"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n" .
			"Content-Transfer-Encoding: base64\r\n" . 
			"Content-Disposition: attachment; filename=smime.p7m\r\n\r\n";

		// Send email body to WebSSL.io. Returns PKCS#7/CMS EnvelopedData 
		$cms = $this->webSSL->cmsEncrypt($emailParts[1], $recipientCertificate, 2);

		// Compose new SMIME Body
		$this->MIMEBody = $cms . "\r\n";	
	}

	public function sendSignedEmail()
	{
		$this->preSend();
		$this->composeSignedEmail();
		$this->postSend();
	}

	public function sendEncryptedEmail($recipientCertPath)
	{
		$this->preSend();
		$this->composeEncryptedEmail($recipientCertPath);
		$this->postSend();
	}

	public function sendSignedAndEncryptedEmail($recipientCertPath)
	{
		$this->preSend();
		$this->composeSignedEmail();
		$this->composeEncryptedEmail($recipientCertPath);
		$this->postSend();
	}
}
