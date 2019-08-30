<?php

class DN{
	public $cn;
	public $c;
	public $l;
	public $s;
	public $o;
	public $ou;
	public $e;
	public $dc;
	
	function __construct($cn, $c, $l, $s, $o, $ou, $e, $dc){
		$this->cn = $cn;
		$this->c = $c;
		$this->l = $l;
		$this->s = $s;
		$this->o = $o;
		$this->ou = $ou;
		$this->e = $e;
		$this->dc = $dc;	
	}
}

class RSAPublicKey{
	public $algorithm;
	public $modulus;
	public $exponent;
	public $point;
	
	function __construct($algorithm, $modulus, $exponent){
		$this->algorithm = $algorithm;
		$this->modulus = $modulus;
		$this->exponent = $exponent;
	}
}

class ECCPublicKey{
	public $algorithm;
	public $point;
	
	function __construct($algorithm, $point){
		$this->algorithm = $algorithm;
		$this->point = $point;
	}
}

class BasicConstraints{
	public $subjectType;
	public $pathLength;
	
	function __construct($subjectType, $pathLength){
		$this->subjectType = $subjectType;
		$this->pathLength = $pathLength;
	}
}

class SubjectAltName{
	public $dns;
	public $ip;
	
	function __construct($dns, $ip){
		$this->dns = $dns;
		$this->ip = $ip;
	}
}

class Signature{
	public $algorithm;
	public $digest;
	public $value;
	
	function __construct($algorithm, $digest, $value){
		$this->algorithm = $algorithm;
		$this->digest = $digest;
		$this->value = $value;
	}
}



?>