# PHP Class for WebSSL with sample for creating a PKI
WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.


**WebSSL.class.php**

```genpkeyGenerateKey```
Generates a cryptographic key pair inside a HSM. 

```x509SignCSR```
Methods within the /x509 URL path handle public key certificates (x509). Use these methods to generate certificates.

```reqGenerateCSR```
Generates a PKCS#10 Certificate Signing Request (CSR) within the HSM

```reqGenKeyCert```
Generates a key pair within the HSM and self signed certificate.

```cmsSign```
Signs data within a HSM as CMS signed-data content, using the signers encrypted private key and certificate.


**CreatePKI.php**

1. Create the Certificate Authority
2. Create the User's key
3. Create the User's Certificate Signing Request
4. Have the Certificate Authority sign the User's Certificate Signing Request
