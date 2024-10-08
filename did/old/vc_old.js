import crypto from 'crypto';  // require 대신 import 사용
import * as circomlibjs from 'circomlibjs';  // circomlibjs 사용
import fs from 'fs';  // 파일 시스템 모듈을 사용하여 키 파일 읽기

async function runPoseidonDIDVerification() {
    // Poseidon 해시 빌드
    const poseidon = await circomlibjs.buildPoseidon();

    // 주어진 DID 문서
    const didDocument = {
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
            "name": "Chungnam National University Information Security Lab"
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
        }
    };

    // 속성 추출
    const attributes = {
        name: didDocument.credentialSubject.name,
        age: didDocument.credentialSubject.age,
        studentNumber: didDocument.credentialSubject.studentNumber,
        alumniName: didDocument.credentialSubject.alumniOf.name,
        // 필요한 추가 속성들
    };

    // Poseidon 해시를 사용한 속성 해시 계산
    function hashAttribute(value) {
        const serialized = JSON.stringify(value);
        const buffer = Buffer.from(serialized);
        const inputArray = [];

        // 입력 크기를 16 이하로 제한
        for (let i = 0; i < buffer.length; i += 31) {
            inputArray.push(BigInt('0x' + buffer.slice(i, i + 31).toString('hex')));
        }

        // Poseidon에 입력할 배열 크기 1에서 16 사이로 제한
        if (inputArray.length > 16) {
            throw new Error('Input array is too large for Poseidon hash');
        }

        const poseidonHash = poseidon(inputArray);
        return poseidon.F.toString(poseidonHash, 16);  // 해시를 16진수로 변환
    }

    // Merkle Tree 구성
    class MerkleTree {
        constructor(leaves) {
            this.leaves = leaves.map(hashAttribute);  // SHA-256 대신 Poseidon 해시 사용
            this.layers = [this.leaves];
            this.buildTree();
        }

        buildTree() {
            let currentLayer = this.leaves;
            while (currentLayer.length > 1) {
                const nextLayer = [];
                for (let i = 0; i < currentLayer.length; i += 2) {
                    if (i + 1 === currentLayer.length) {
                        nextLayer.push(currentLayer[i]);
                    } else {
                        const combined = currentLayer[i] + currentLayer[i + 1];
                        nextLayer.push(hashAttribute(combined));
                    }
                }
                this.layers.push(nextLayer);
                currentLayer = nextLayer;
            }
        }

        getRoot() {
            return this.layers[this.layers.length - 1][0];
        }

        getProof(leafIndex) {
            let proof = [];
            let index = leafIndex;
            for (let i = 0; i < this.layers.length - 1; i++) {
                const layer = this.layers[i];
                const isRightNode = index % 2;
                const siblingIndex = isRightNode ? index - 1 : index + 1;
                if (siblingIndex < layer.length) {
                    proof.push({
                        data: layer[siblingIndex],
                        position: isRightNode ? 'left' : 'right'
                    });
                }
                index = Math.floor(index / 2);
            }
            return proof;
        }
    }

    // Merkle Tree 생성
    const attributeValues = Object.values(attributes);
    const merkleTree = new MerkleTree(attributeValues);
    const merkleRoot = merkleTree.getRoot();

    // 특정 속성의 Merkle Proof 생성 (예: age)
    const ageIndex = Object.keys(attributes).indexOf('age');
    const ageProof = merkleTree.getProof(ageIndex);

    // 발행자의 PEM 형식 개인 키로 Merkle Root에 서명
    const privateKey = fs.readFileSync('./private_key.pem', 'utf8');

    // Ed25519 서명 생성
    const signature = crypto.sign(null, Buffer.from(merkleRoot, 'hex'), privateKey);

    // Verifiable Credential 생성
    const verifiableCredential = {
        ...didDocument,
        proof: {
            type: 'Ed25519Signature2018',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: didDocument.issuer.id,
            merkleRoot: merkleRoot,
            signatureValue: signature.toString('hex')
        }
    };

    console.log('Verifiable Credential:', JSON.stringify(verifiableCredential, null, 2));
    fs.writeFileSync('./vc_old.json', JSON.stringify(verifiableCredential, null, 2), 'utf8');
}

runPoseidonDIDVerification();
