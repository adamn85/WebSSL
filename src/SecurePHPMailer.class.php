<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require '../PHPMailer/Exception.php';
require '../PHPMailer/PHPMailer.php';
require '../PHPMailer/SMTP.php';
require 'WebSSL.class.php';

/*
*/
class SecurePHPMailer extends PHPMailer
{
	private $webSSL;
	private $sendersCertificate;
	private $sendersEncryptedKey;

	public function __construct($sendersCertPath, $sendersKeyPath) 
	{
        $this->webSSL = new WebSSL();
        $this->sendersCertificate = file_get_contents($sendersCertPath, FILE_USE_INCLUDE_PATH);
        $this->sendersKey = file_get_contents($sendersKeyPath, FILE_USE_INCLUDE_PATH);
        parent::__construct();
    }

	public function sendSignedEmail()
	{
		// Create new MIME boundary
		$boundary = $this->generateId();

		// Get PHPMailers composed Email prior to sending
		$this->preSend();

		// Split original email 
		$emailParts = explode("MIME-Version: 1.0\r\n", $this->getSentMimeMessage());

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
		
		// Send newly constructed Email
		$this->postSend();
	}

	public function sendEncryptedEmail($recipientCertPath)
	{
		// Open PEM Certificate 
		$recipientCertificate = file_get_contents($recipientCertPath, FILE_USE_INCLUDE_PATH);
		
		// Get PHPMailers composed Email prior to sending
		$this->preSend();

		// Split original email 
		$emailParts = explode("MIME-Version: 1.0\r\n", $this->getSentMimeMessage());

		// Compose new SMIME Header
		$this->MIMEHeader = $emailParts[0] .
			"MIME-Version: 1.0\r\n" .
			"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n" .
			"Content-Transfer-Encoding: base64\r\n" . 
			"Content-Disposition: attachment; filename=smime.p7m\r\n\r\n";

		// Send email body to WebSSL.io. Returns PKCS#7/CMS EnvelopedData 
		$cms = $this->webSSL->cmsEncrypt($emailParts[1], $recipientCertificate);

		// Compose new SMIME Body
		$this->MIMEBody = $cms . "\r\n";
		
		// Send newly constructed Email
		$this->postSend();
	}

	public function sendSignedAndEncryptedEmail($recipientCertPath)
	{
		// Open PEM Certificate 
		$recipientCertificate = file_get_contents($recipientCertPath, FILE_USE_INCLUDE_PATH);
		
		// Get PHPMailers composed Email prior to sending
		$this->preSend();

		// Split original email 
		$emailParts = explode("MIME-Version: 1.0\r\n", $this->getSentMimeMessage());

		// Compose new SMIME Header
		$this->MIMEHeader = $emailParts[0] .
			"MIME-Version: 1.0\r\n" .
			"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n" .
			"Content-Transfer-Encoding: base64\r\n" . 
			"Content-Disposition: attachment; filename=smime.p7m\r\n\r\n";

		// Send email body to WebSSL.io. Returns PKCS#7/CMS EnvelopedData 
		$cms = $this->webSSL->cmsSignAndEncrypt($emailParts[1], $this->sendersKey, $this->sendersCertificate, $recipientCertificate);

		// Compose new SMIME Body
		$this->MIMEBody = $cms . "\r\n";
		
		// Send newly constructed Email
		$this->postSend();
	}

}
