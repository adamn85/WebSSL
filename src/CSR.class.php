<?php

require_once '../src/Structures.class.php';

class CSRException extends Exception { }
 
class CSR {

	public $subject;
	public $publicKeyInfo;
	public $keyUsage;
	public $extendedKeyUsage;	
	public $subjectKeyId;
	public $basicConstraints;
	public $subjectAltName;
	public $signature;

	function __construct($csrArray){
		
		$subject_cn = $subject_c = $subject_l = $subject_s = $subject_o = $subject_ou = $subject_e = $subject_dc = null; 
		$dns = $ip = "Not Present";

		if(!array_key_exists("subject", $csrArray)) 	  throw new CSRException('Subject not present');
		if(!array_key_exists("publicKeyInfo", $csrArray)) throw new CSRException('Public Key Info not present');
		
		if(!array_key_exists("commonName",		  $csrArray['subject'])) throw new CSRException('Common Name not present');
		if(array_key_exists("commonName",  		  $csrArray['subject'])) $subject_cn = $csrArray['subject']['commonName'];
		if(array_key_exists("country",  		  $csrArray['subject'])) $subject_c = $csrArray['subject']['country'];
		if(array_key_exists("locality",  		  $csrArray['subject'])) $subject_l = $csrArray['subject']['locality'];
		if(array_key_exists("state",  			  $csrArray['subject'])) $subject_s = $csrArray['subject']['state'];
		if(array_key_exists("organisation",  	  $csrArray['subject'])) $subject_o = $csrArray['subject']['organisation'];
		if(array_key_exists("organisationalUnit", $csrArray['subject'])) $subject_ou = $csrArray['subject']['organisationalUnit'];
		if(array_key_exists("email",  			  $csrArray['subject'])) $subject_e = $csrArray['subject']['email'];
		if(array_key_exists("domainComponent", 	  $csrArray['subject'])) $subject_dc = $csrArray['subject']['domainComponent'];
		$this->subject = new DN($subject_cn, $subject_c, $subject_l, $subject_s, $subject_o, $subject_ou, $subject_e, $subject_dc);
		
		if(array_key_exists("modulus", $csrArray['publicKeyInfo'])	&& array_key_exists("exponent", $csrArray['publicKeyInfo'])){
			$this->publicKeyInfo = new RSAPublicKey($csrArray['publicKeyInfo']['algorithm'], 
													$csrArray['publicKeyInfo']['modulus'],
													$csrArray['publicKeyInfo']['exponent']);
		}
		if(array_key_exists("point", $csrArray['publicKeyInfo'])){
			$this->publicKeyInfo = new ECCPublicKey($csrArray['publicKeyInfo']['algorithm'],
													$csrArray['publicKeyInfo']['point']);
		}
		
		if(array_key_exists("subjectAltName", $csrArray)){	
			if(array_key_exists("DNS", $csrArray['subjectAltName'])) $dns = $csrArray['subjectAltName']['DNS'];
			if(array_key_exists("IP", $csrArray['subjectAltName']))  $ip = $csrArray['subjectAltName']['IP'];
			$this->subjectAltName = new SubjectAltName($dns, $ip);
		}

		if(array_key_exists("subjectKeyId", $csrArray))    $this->subjectKeyId = $csrArray['subjectKeyId'];	
		if(array_key_exists("keyUsage", $csrArray)) 	   $this->keyUsage = implode(", ", $csrArray['keyUsage']);	
		if(array_key_exists("enhancedKeyUsage", $csrArray))$this->extendedKeyUsage = implode(", ", $csrArray['enhancedKeyUsage']);
		
		if(array_key_exists("basicConstraints", $csrArray)){
			$this->basicConstraints = new BasicConstraints($csrArray['basicConstraints']['subjectType'],
														   $csrArray['basicConstraints']['pathLengthConstraint']);
		}
	    if(array_key_exists("signature", $csrArray)){
			$this->signature = new Signature($csrArray['signature']['algorithm'],
											 $csrArray['signature']['digest'],
											 $csrArray['signature']['value']);
		}
	}

	function toString(){
		
		$keyUsage = $extendedKeyUsage = $subjectKeyId = $basicConstraints = $subjectAltName = $signature = "";
		
		$subject = "\n\tSubject: ";
		$subject .= "\n\t\tCommon Name: " . $this->subject->cn;	
		if($this->subject->l != null)  $subject .= "\n\t\tLocality: " . $this->subject->l;
		if($this->subject->s != null)  $subject .= "\n\t\tState: " . $this->subject->s;
		if($this->subject->o != null)  $subject .= "\n\t\tOrganisation: " . $this->subject->o;
		if($this->subject->ou != null) $subject .= "\n\t\tOrganisationalUnit: " . $this->subject->ou;
		if($this->subject->c != null)  $subject .= "\n\t\tCountry: " . $this->subject->c;
		if($this->subject->e != null)  $subject .= "\n\t\tEmail: " . $this->subject->e;
		if($this->subject->dc != null) $subject .= "\n\t\tDomain Component: " . $this->subject->dc;
		
		$publicKeyInfo = "\n\tPublic Key:";	
		$publicKeyInfo .= "\n\t\tAlgorithm: " . $this->publicKeyInfo->algorithm;
		if($this->publicKeyInfo instanceof RSAPublicKey){
			$publicKeyInfo .= "\n\t\tModulus: " . $this->publicKeyInfo->modulus;
			$publicKeyInfo .= "\n\t\tExponent: " . $this->publicKeyInfo->exponent;
		}
		else if($this->publicKeyInfo instanceof ECCPublicKey){
			$publicKeyInfo .= "\n\t\tPoint: " . $this->publicKeyInfo->point;
		}
		
		if(strlen($this->keyUsage) > 0) 		$keyUsage = "\n\tKey Usage: \n\t\t" . $this->keyUsage;
		if(strlen($this->extendedKeyUsage) > 0) $extendedKeyUsage = "\n\tExtended Usage: \n\t\t" . $this->extendedKeyUsage;
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
		
		return "Certificate Signing Request:\n" . $subject. $publicKeyInfo . $keyUsage . $extendedKeyUsage . $subjectKeyId . $basicConstraints . $subjectAltName . $signature;
	}
}

?>