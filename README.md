# Verifiable Credential Scheme with BabyJubJub-based zk-SNARK and SMT

This project introduces the **BabyJubJubSMTSignature2024** Verifiable Credential (VC) scheme, which leverages Sparse Merkle Trees (SMT) and BabyJubJub-based signatures. This scheme enhances the traditional Verifiable Credential approach by incorporating the privacy-preserving and efficient verification features of zk-SNARKs, allowing for external credential verification without dependence on centralized entities or intermediaries.

The BabyJubJubSMTSignature2024 scheme is highly flexible, enabling the definition of various Verifiable Presentation (VP) schemes in Circom based on SMT structures. This approach supports the creation of custom verification logic for different attributes of credentials, offering improved scalability and interoperability in decentralized systems.

**The goal is to eliminate all trust dependencies except for the issuer and to establish a system that can also be used in smart contracts.**

### Key Features:
- **zk-SNARK-based Verification**: Efficient and privacy-preserving verification of credentials without revealing the underlying data.
- **SMT-based Attribute Verification**: Ensures that the attributes (e.g., age, university affiliation) are securely stored and verified in a Merkle tree structure.
- **BabyJubJub Signature**: Uses the lightweight BabyJubJub elliptic curve for signature verification, optimized for zk-SNARK applications.
- **Flexible VP Scheme Definition**: Supports defining multiple Verifiable Presentation schemes for different verification scenarios.

## Example Verifiable Credential
Below is an example of a Verifiable Credential (VC) using the BabyJubJubSMTSignature2024 scheme:

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
    "proofPurpose": "verificationMethod",
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
### Circuit Explanation (Example of a VP Scheme)
The following explains one possible Verifiable Presentation (VP) scheme using the BabyJubJubSMTSignature2024:

- SMT Inclusion Proof: Each attribute (e.g., age, alumniOf, name) is verified by a separate SMT verifier, ensuring that the provided attribute values are part of the Merkle tree using the root hash as a reference.

- EdDSA Signature Verification: The issuer’s signature over the Merkle root hash is verified using EdDSA. This proves that the root hash, which represents the credential's attributes, was signed by the issuer’s public key, ensuring the authenticity of the credential.

- Attribute Validation: Specifically for the age attribute, the circuit includes a comparator that checks whether the age in the SMT proof is greater than or equal to 25, enforcing an age requirement as part of the credential validation.

## Usage and Applications:
This scheme can be used in various decentralized applications (DApps) that require secure, scalable, and privacy-preserving verification of credentials, such as identity verification, proof of age, or university affiliation. By using zk-SNARK and SMT-based structures, it reduces the need for centralized verification authorities, making it an ideal solution for decentralized identity (DID) systems and blockchain-based ecosystems.

## License
This project is open-sourced under the MIT License. Feel free to use, modify, and distribute it for personal or commercial use.




