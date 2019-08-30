<?php

require_once '../src/Structures.class.php';

class CertificateException extends Exception { }
 
class Certificate {

	public $version;
	public $serialNumber;
	public $subject;
	public $issuer;
	public $publicKeyInfo;
	public $validFrom;
	public $validTo;
	public $keyUsage;
	public $extendedKeyUsage;	
	public $subjectKeyId;
	public $authorityKeyId;
	public $basicConstraints;
	public $subjectAltName;
	public $signature;

	function __construct($certArray){
		
		$subject_cn = $subject_c = $subject_l = $subject_s = $subject_o = $subject_ou = $subject_e = $subject_dc = null; 
		$issuer_cn = $issuer_c = $issuer_l = $issuer_s = $issuer_o = $issuer_ou = $issuer_e = $issuer_dc = null; 
		$dns = $ip = "Not Present";

		if(!array_key_exists("version", $certArray)) 	   throw new CertificateException('Version not present');
		if(!array_key_exists("serialNumber", $certArray))  throw new CertificateException('Serial Number not present');
		if(!array_key_exists("subject", $certArray)) 	   throw new CertificateException('Subject not present');
		if(!array_key_exists("issuer", $certArray)) 	   throw new CertificateException('Issuer not present');
		if(!array_key_exists("validFrom", $certArray))	   throw new CertificateException('Valid from not present');
		if(!array_key_exists("validTo", $certArray)) 	   throw new CertificateException('Valid to not present');
		if(!array_key_exists("publicKeyInfo", $certArray)) throw new CertificateException('Public Key Info not present');
			
		$this->version = $certArray['version'];
		$this->serialNumber = $certArray['serialNumber'];
		
		if(!array_key_exists("commonName",		  $certArray['subject'])) throw new CertificateException('Common Name not present');
		if(array_key_exists("commonName",  		  $certArray['subject'])) $subject_cn = $certArray['subject']['commonName'];
		if(array_key_exists("country",  		  $certArray['subject'])) $subject_c = $certArray['subject']['country'];
		if(array_key_exists("locality",  		  $certArray['subject'])) $subject_l = $certArray['subject']['locality'];
		if(array_key_exists("state",  			  $certArray['subject'])) $subject_s = $certArray['subject']['state'];
		if(array_key_exists("organisation",  	  $certArray['subject'])) $subject_o = $certArray['subject']['organisation'];
		if(array_key_exists("organisationalUnit", $certArray['subject'])) $subject_ou = $certArray['subject']['organisationalUnit'];
		if(array_key_exists("email",  			  $certArray['subject'])) $subject_e = $certArray['subject']['email'];
		if(array_key_exists("domainComponent", 	  $certArray['subject'])) $subject_dc = $certArray['subject']['domainComponent'];
		$this->subject = new DN($subject_cn, $subject_c, $subject_l, $subject_s, $subject_o, $subject_ou, $subject_e, $subject_dc);
		
		if(!array_key_exists("commonName", 		  $certArray['issuer'])) throw new CertificateException('Common Name not present');
		if(array_key_exists("commonName",  		  $certArray['issuer'])) $issuer_cn = $certArray['issuer']['commonName'];
		if(array_key_exists("country",  		  $certArray['issuer'])) $issuer_c = $certArray['issuer']['country'];
		if(array_key_exists("locality",   		  $certArray['issuer'])) $issuer_l = $certArray['issuer']['locality'];
		if(array_key_exists("state",   			  $certArray['issuer'])) $issuer_s = $certArray['issuer']['state'];
		if(array_key_exists("organisation",       $certArray['issuer'])) $issuer_o = $certArray['issuer']['organisation'];
		if(array_key_exists("organisationalUnit", $certArray['issuer'])) $issuer_ou = $certArray['issuer']['organisationalUnit'];
		if(array_key_exists("email",   			  $certArray['issuer'])) $issuer_e = $certArray['issuer']['email'];
		if(array_key_exists("domainComponent",    $certArray['issuer'])) $issuer_dc = $certArray['issuer']['domainComponent'];
		$this->issuer = new DN($issuer_cn, $issuer_c, $issuer_l, $issuer_s, $issuer_o, $issuer_ou, $issuer_e, $issuer_dc);
		
		if(array_key_exists("modulus", $certArray['publicKeyInfo'])	&& array_key_exists("exponent", $certArray['publicKeyInfo'])){
			$this->publicKeyInfo = new RSAPublicKey($certArray['publicKeyInfo']['algorithm'], 
													$certArray['publicKeyInfo']['modulus'],
													$certArray['publicKeyInfo']['exponent']);
		}
		if(array_key_exists("point", $certArray['publicKeyInfo'])){
			$this->publicKeyInfo = new ECCPublicKey($certArray['publicKeyInfo']['algorithm'],
													$certArray['publicKeyInfo']['point']);
		}
		
		$this->validFrom = $certArray['validFrom'];
		$this->validTo = $certArray['validTo'];	
		
		if(array_key_exists("authorityKeyId", $certArray))  $this->authorityKeyId = $certArray['authorityKeyId'];
		if(array_key_exists("subjectKeyId", $certArray)) 	$this->subjectKeyId = $certArray['subjectKeyId'];	
		if(array_key_exists("keyUsage", $certArray)) 		$this->keyUsage = implode(", ", $certArray['keyUsage']);	
		if(array_key_exists("enhancedKeyUsage", $certArray))$this->extendedKeyUsage = implode(", ", $certArray['enhancedKeyUsage']);
		
		if(array_key_exists("basicConstraints", $certArray)){
			$this->basicConstraints = new BasicConstraints($certArray['basicConstraints']['subjectType'],
														   $certArray['basicConstraints']['pathLengthConstraint']);
		}
		if(array_key_exists("subjectAltName", $certArray)){	
			if(array_key_exists("DNS", $certArray['subjectAltName'])) $dns = $certArray['subjectAltName']['DNS'];
			if(array_key_exists("IP", $certArray['subjectAltName']))  $ip = $certArray['subjectAltName']['IP'];
			$this->subjectAltName = new SubjectAltName($dns, $ip);
		}
	    if(array_key_exists("signature", $certArray)){
			$this->signature = new Signature($certArray['signature']['algorithm'],
											 $certArray['signature']['digest'],
											 $certArray['signature']['value']);
		}
	}

	function toString(){
		
		$keyUsage = $extendedKeyUsage = $authorityKeyId = $subjectKeyId = $basicConstraints = $subjectAltName = $signature = "";
		
		$version = "\n\tVersion: \n\t\t" . $this->version;
		$serialNumber = "\n\tSerial Number: \n\t\t" . $this->serialNumber;
		
		$subject = "\n\tSubject: ";
		$subject .= "\n\t\tCommon Name: " . $this->subject->cn;	
		if($this->subject->l != null)  $subject .= "\n\t\tLocality: " . $this->subject->l;
		if($this->subject->s != null)  $subject .= "\n\t\tState: " . $this->subject->s;
		if($this->subject->o != null)  $subject .= "\n\t\tOrganisation: " . $this->subject->o;
		if($this->subject->ou != null) $subject .= "\n\t\tOrganisationalUnit: " . $this->subject->ou;
		if($this->subject->c != null)  $subject .= "\n\t\tCountry: " . $this->subject->c;
		if($this->subject->e != null)  $subject .= "\n\t\tEmail: " . $this->subject->e;
		if($this->subject->dc != null) $subject .= "\n\t\tDomain Component: " . $this->subject->dc;
		
		$issuer = "\n\tIssuer: ";
		$issuer .= "\n\t\tCommon Name: " . $this->subject->cn;
		if($this->issuer->l != null)  $issuer .= "\n\t\tLocality: " . $this->issuer->l;
		if($this->issuer->s != null)  $issuer .= "\n\t\tState: " . $this->issuer->s;
		if($this->issuer->o != null)  $issuer .= "\n\t\tOrganisation: " . $this->issuer->o;
		if($this->issuer->ou != null) $issuer .= "\n\t\tOrganisationalUnit: " . $this->issuer->ou;
		if($this->issuer->c != null)  $issuer .= "\n\t\tCountry: " . $this->issuer->c;
		if($this->issuer->e != null)  $issuer .= "\n\t\tEmail: " . $this->issuer->e;
		if($this->issuer->dc != null) $issuer .= "\n\t\tDomain Component: " . $this->issuer->dc;
		
		$publicKeyInfo = "\n\tPublic Key:";	
		$publicKeyInfo .= "\n\t\tAlgorithm: " . $this->publicKeyInfo->algorithm;
		if($this->publicKeyInfo instanceof RSAPublicKey){
			$publicKeyInfo .= "\n\t\tModulus: " . $this->publicKeyInfo->modulus;
			$publicKeyInfo .= "\n\t\tExponent: " . $this->publicKeyInfo->exponent;
		}
		else if($this->publicKeyInfo instanceof ECCPublicKey){
			$publicKeyInfo .= "\n\t\tPoint: " . $this->publicKeyInfo->point;
		}
		
		$validFrom = "\n\tValid From: \n\t\t" . $this->validFrom;
		$validTo = "\n\tValid To: \n\t\t" . $this->validTo;
		if(strlen($this->keyUsage) > 0) 		$keyUsage = "\n\tKey Usage: \n\t\t" . $this->keyUsage;
		if(strlen($this->extendedKeyUsage) > 0) $extendedKeyUsage = "\n\tExtended Usage: \n\t\t" . $this->extendedKeyUsage;
		if(strlen($this->authorityKeyId) > 0) 	$authorityKeyId = "\n\tAuthority Key Id: \n\t\t" . $this->authorityKeyId;
		if(strlen($this->subjectKeyId) > 0) 	$subjectKeyId = "\n\tSubject Key Id: \n\t\t" . $this->subjectKeyId;

		if($this->basicConstraints instanceof BasicConstraints){
			$basicConstraints = "\n\tBasic Constraints:";
			$basicConstraints .= "\n\t\tSubject Type: " . $this->basicConstraints->subjectType;
			$basicConstraints .= "\n\t\tPath Length: " . $this->basicConstraints->pathLength;
		}
		
		if($this->subjectAltName instanceof SubjectAltName){
			$subjectAltName = "\n\tSubject Alternative Name:";
			if(strlen($this->subjectAltName->dns) > 0) $subjectAltName .= "\n\t\tDNS: " . $this->subjectAltName->dns;
			if(strlen($this->subjectAltName->ip) > 0)  $subjectAltName .= "\n\t\tIP: " . $this->subjectAltName->ip;
		}
		
		if($this->signature instanceof Signature){
			$signature = "\n\tSignature:";
			$signature .= "\n\t\tAlgorithm: " . $this->signature->algorithm;
			$signature .= "\n\t\tDigest: " . $this->signature->digest;
			$signature .= "\n\t\tValue: " . $this->signature->value;
		}
		
		return "Certificate:\n" . $version . $serialNumber . $subject. $issuer . $publicKeyInfo . $validFrom. $validTo . $keyUsage . $extendedKeyUsage . $authorityKeyId . $subjectKeyId . $basicConstraints . $subjectAltName . $signature;
	}
	
}


?>