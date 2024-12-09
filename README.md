# Ledger-Free Decentralized Identifier (DID) Authentication Scheme

논문 작성중에 있습니다.
논문(미완) 초안: https://satisfying-scorpio-da7.notion.site/zk-Embedded-Authentication-1-1575e32c595580409254de94a76dfa2b?pvs=4

## Abstract
This repository implements a **Ledger-Free Decentralized Identifier (DID) Authentication Scheme** that overcomes interoperability and flexibility limitations inherent to ledger-based DID systems. By leveraging **Sparse Merkle Tree (SMT)** for Verifiable Credential (VC) structuring, **Zero-Knowledge Proofs (zk-SNARK)** for privacy-preserving authentication, and **Wallet-Based Embedded Authentication**, this approach enables decentralized trust models without relying on a centralized ledger or trust anchors. The project incorporates zk-SNARK-friendly cryptographic primitives, such as the **BabyJubJub curve**, to ensure cross-chain operability and standard compliance (e.g., **EIP-712**).

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
   - Implements EIP-712 for structured signing and BabyJubJub for zk-SNARK compatibility.  
   - Supports interoperability across multiple blockchain networks.


##
