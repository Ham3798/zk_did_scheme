# Verifiable Credential Scheme with BabyJubJub-based zk-SNARK and SMT
This project extends the existing Verifiable Credential (VC) scheme that uses EDDSA2018 signatures by proposing a new signature scheme combining BabyJubJub-based EDDSA signatures and Sparse Merkle Tree (SMT). 
**The primary goal of this system is to allow credential verification to be conducted externally using a zk-SNARK-based verification mechanism, thereby eliminating all dependencies except for trust in the issuer.** This enables verification to be performed independently, enhancing decentralization and reducing reliance on centralized trust.

The scheme leverages zk-SNARK technology to perform attribute verification securely and efficiently while ensuring user privacy. While similar to the traditional EDDSA2018, this scheme operates on the BabyJubJub curve, offering lighter signature processing and improved interoperability. It is particularly focused on improving the interoperability of hardware-mapped VC documents in a DID environment.

## Example Verifiable Credential
Here is an example of a Verifiable Credential (VC) example:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.example.org/examples/v1"
  ],
  "id": "http://chungnam.ac.kr/credentials/3732",
  "type": [
    "VerifiableCredential",
    "AlumniCredential"
  ],
  "issuer": {
    "id": "https://infosec.chungnam.ac.kr",
    "name": "Chungnam National University Information Security Lab",
    "publicKey": {
      "Ax": "13277427435165878497778222415993513565335242147425444199013288855685581939618",
      "Ay": "13622229784656158136036771217484571176836296686641868549125388198837476602820"
    }
  },
  "issuanceDate": "2024-02-11T09:30:24Z",
  "credentialSubject": {
    "id": "did:example:abcdef1234567890",
    "name": "ham3798",
    "age": 25,
    "studentNumber": "201902769",
    "alumniOf": {
      "id": "did:example:c34fb4561237890",
      "name": "Chungnam National University",
      "department": "Information Security Lab"
    }
  },
  "proof": {
    "type": "BabyJubJubSMTSignature2024",
    "created": "2024-10-08T05:59:43.348Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://infosec.chungnam.ac.kr",
    "merkleRoot": "176,113,248,159,95,186,151,221,221,94,150,40,177,156,132,61,209,46,57,221,176,188,79,122,39,33,214,72,77,255,225,5",
    "signature": {
      "R8x": "14843327923499602530760840822364653819560149483324056861844414827173045711128",
      "R8y": "16624741311753369209800270717954129820251768033844592664257222687029635194829",
      "S": "2003340101055013093731532733602979271886157286292523269931749695412007991258"
    }
  }
}
```

## explanation of the example circuit:

* SMT Inclusion Proofs : The circuit includes separate SMT verifiers for each attribute—age, alumniOf, and name. These verifiers ensure that the given attribute values are valid and part of the Merkle tree, using the root hash as a reference.

* EdDSA Signature Verification: An EdDSA signature verifier checks the issuer’s signature against the Merkle root hash, ensuring that the root hash was signed by the issuer’s public key and proving the authenticity of the credential.

* Attribute Validation: Specifically for the age attribute, a comparator is used to check whether the value from the SMT proof is greater than or equal to 25, enforcing an age requirement as part of the credential validation.


