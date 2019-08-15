# PHP Class for WebSSL with sample for creating a PKI
WebSSL is a cryptographic library built to run within a Hardware Security Module and provides a universally accessible interface.


**WebSSL.class.php**

**```genpkeyGenerateKey```**
Generates a cryptographic key pair inside a HSM. The private key is AES encrypted by a HSM and returned in a PEM encoded encrypted private key structure. The public key is returned PEM encoded.

```$algorithm``` **Type** String **Required** yes **Description** Algorithms (rsa-2048, rsa-4096, ecc-p256, rsa-p521).

**```x509SignCSR```**
Signs a Certifcate Signing Request (CSR) in the HSM and composes an x509 certificate.

```$days``` **Type** String **Required** yes **Description** The number of days the certificate will be valid for.
```$digest``` **Type** String **Required** yes **Description** CSR digest (sha-256)
```$csr``` **Type** String **Required** yes **Description** Certificate Signing Request (PEM encoded) 
```$signerCert``` **Type** String **Required** yes **Description** Signers x509 certficate (PEM encoded)
```$inKey``` **Type** String **Required** yes **Description** Signers key (PEM encoded encrypted private key) 

**```reqGenerateCSR```**
Generates a PKCS#10 Certificate Signing Request (CSR) within the HSM, by signing the applicants distinguished name fields with their private key.

```$inKey``` **Type** String **Required** yes **Description** Signers key (PEM encoded encrypted private key)
```$csrDigest``` **Type** String **Required** yes **Description** CSR digest (sha-256)
```$dn``` **Type** object **Required** yes **Description** CSR Distinguished names

**```reqGenKeyCert```**
Generates a key pair within the HSM and self signed certificate.

```$algorithm``` **Type** String **Required** yes **Description** Algorithms (rsa-2048, rsa-4096, ecc-p256, ecc-p521).
```$certDays``` **Type** String **Required** yes **Description** The number of days the certificate will be valid for.
```$csrDigest``` **Type** object **Required** yes **Description** CSR digest (sha-256)
```$certSubjectType``` **Type** String **Required** yes **Description** Certificate subject type (CA, End Entity)
```$dn``` **Type** object **Required** yes **Description** CSR Distinguished names

**```cmsSign```**
Signs data within a HSM as CMS signed-data content, using the signers encrypted private key and certificate.
```$data``` **Type** String **Required** yes **Description**  Data to sign (Base64 encoded)
```$signersKey``` **Type** String **Required** yes **Description** Signers key (PEM encoded encrypted private key)
```$signerCert``` **Type** object **Required** yes **Description** Signers Certificate (PEM encoded certificate)

**CreatePKI.php**

1. Create the Certificate Authority
2. Create the User's key
3. Create the User's Certificate Signing Request
4. Have the Certificate Authority sign the User's Certificate Signing Request
