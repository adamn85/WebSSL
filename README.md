# A collection of PHP classes for utilising WebSSL.io
WebSSL.io is a HTTP accessible Hardware Security Module(HSM) with a variety of cryptographic functions.

## SecurePHPMailer.class.php
This class extends the functionality of PHPMailer project's PHPMailer class. (https://github.com/PHPMailer/PHPMailer/)
The extended class provides S/MIME signed an encrypted emailing functionality. 

## send_mail.php
Sample code demonstrating how to use the SecurePHPMailer class. 

## WebSSL.class.php
This class handles the composition and transfer of HTTP-JSON requests and responses to a remote HSM. 
The remote HSM provides the WebSSL HTTP API. This class requires PHP's Client URL Library.
- [WebSSL.io](https://www.webssl.io)
- [Libcurl](https://www.php.net/manual/en/book.curl.php)

## create_pki.php
Sample code for creating a Keys and Certificates and setting up your own development Public Key Infrastructure.














