# Ledger-Free Decentralized Identifier (DID) Authentication Scheme

## Abstract
This repository implements a **Ledger-Free Decentralized Identifier (DID) Authentication Scheme** that overcomes interoperability and flexibility limitations inherent to ledger-based DID systems. By leveraging **Sparse Merkle Tree (SMT)** for Verifiable Credential (VC) structuring, **Zero-Knowledge Proofs (zk-SNARK)** for privacy-preserving authentication, and **Wallet-Based Embedded Authentication**, this approach enables decentralized trust models without relying on a centralized ledger or trust anchors.

---

## Features
1. **Ledger-Free Trust Model**  
   - Eliminates dependency on distributed ledgers and their governance mechanisms.  
   - Enables auditable data structures for DID authentication.

2. **Sparse Merkle Tree-Based VC Structuring**  
   - Efficient inclusion/exclusion proofs for attributes.  
   - Allows aggregation of all VC attributes into a single cryptographic Merkle root.

3. **Zero-Knowledge Proofs for Privacy**  
   - Proves selective attributes without revealing entire credentials.  
   - Example: Prove "age ≥ 18" without disclosing the exact value.

4. **Cross-Chain Compatibility**  
   - Supports interoperability across multiple blockchain networks.


##
