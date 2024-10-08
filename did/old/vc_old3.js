import fs from 'fs';
import { buildEddsa, buildBabyjub, buildPoseidon, newMemEmptyTrie } from 'circomlibjs';

function bigintToUint8Array(bigint) {
    let hex = bigint.toString(16);
    if (hex.length % 2) {
        hex = '0' + hex; // 홀수일 경우 앞에 0을 추가
    }
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    let i = 0;
    let j = 0;
    while (i < len) {
        u8[i] = parseInt(hex.slice(j, j + 2), 16);
        i += 1;
        j += 2;
    }
    return u8;
}

async function generateVC() {
    // circomlibjs의 필요한 컴포넌트 초기화
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = poseidon.F; // 필드 연산 객체

    // 개인 키 읽기 (PEM 형식)
    const issuerPrivateKeyHex = fs.readFileSync('./private_key.pem', 'utf8').trim();
    const issuerPrivateKey = Buffer.from(issuerPrivateKeyHex, 'hex');

    // 발행자 공개 키 생성
    const issuerPublicKey = eddsa.prv2pub(issuerPrivateKey);

    // DID 문서 (Verifiable Credential Subject)
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

    // 속성 추출 및 키 할당
    const attributes = didDocument.credentialSubject;
    const attributeKeys = {};
    let keyIndex = 0n;
    for (const key in attributes) {
        if (key !== 'id') {
            attributeKeys[key] = keyIndex++;
        }
    }

    // circomlibjs를 사용한 Sparse Merkle Tree(SMT) 생성
    const tree = await newMemEmptyTrie();

    // 속성을 해싱하고 SMT에 삽입
    for (const [key, value] of Object.entries(attributes)) {
        if (key !== 'id') {
            const keyBigInt = BigInt(attributeKeys[key]);
            let valueBigInt;
            if (typeof value === 'number') {
                valueBigInt = BigInt(value);
            } else {
                const valueBuffer = Buffer.from(value.toString(), 'utf8');
                valueBigInt = BigInt('0x' + valueBuffer.toString('hex'));
            }
            // Poseidon 해시 사용
            const hashedValue = poseidon([valueBigInt]);
            await tree.insert(keyBigInt, hashedValue);
        }
    }

    // SMT의 Merkle 루트 계산
    const merkleRoot = tree.root;

    // 'age' 속성에 대한 Merkle 증명 생성
    const ageKey = BigInt(attributeKeys['age']);
    const ageValue = attributes['age'];
    const { siblings: ageSiblings, isOld0: isOld0Age, value: oldAgeValue } = await tree.find(ageKey);

    // 'alumniOf.name' 속성에 대한 Merkle 증명 생성
    const alumniKey = BigInt(attributeKeys['alumniOf']);
    const alumniValue = attributes['alumniOf'].name;
    const alumniValueBigInt = BigInt('0x' + Buffer.from(alumniValue, 'utf8').toString('hex'));
    const { siblings: alumniSiblings, isOld0: isOld0Alumni, value: oldAlumniValue } = await tree.find(alumniKey);

    // Merkle 루트를 EdDSA로 서명
    const merkleRootField = F.toObject(merkleRoot);
    const merkleRootArray = bigintToUint8Array(merkleRootField);

    // Sign the Merkle root using EdDSA
    const signature = eddsa.signPoseidon(issuerPrivateKey, merkleRootArray);

    // Verifiable Credential 생성
    const verifiableCredential = {
        ...didDocument,
        proof: {
            type: 'BabyJubJubPoseidonSignature2024',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: didDocument.issuer.id,
            merkleRoot: merkleRootField.toString(),
            signature: {
                R8x: signature.R8[0].toString(),
                R8y: signature.R8[1].toString(),
                S: signature.S.toString()
            }
        },
        issuer: {
            ...didDocument.issuer,
            publicKey: {
                Ax: issuerPublicKey[0].toString(),
                Ay: issuerPublicKey[1].toString()
            }
        }
    };

    // VC를 JSON 파일로 저장
    fs.writeFileSync('./vc.json', JSON.stringify(verifiableCredential, null, 2), 'utf8');

    // Circom 회로에 사용할 입력 데이터 생성
    const inputs = {
        // enabled: 1,
        root: merkleRootField.toString(),
        siblings: ageSiblings.map(s => s.toString()),
        alumniSiblings: alumniSiblings.map(s => s.toString()),
        oldKey: ageKey.toString(),
        oldValue: oldAgeValue ? oldAgeValue.toString() : '0',
        isOld0: isOld0Age ? 1 : 0,
        alumniKey: alumniKey.toString(),
        alumniValue: oldAlumniValue ? oldAlumniValue.toString() : '0',
        isAlumniOld0: isOld0Alumni ? 1 : 0,
        age: ageValue.toString(),
        Ax: issuerPublicKey[0].toString(),
        Ay: issuerPublicKey[1].toString(),
        R8x: signature.R8[0].toString(),
        R8y: signature.R8[1].toString(),
        S: signature.S.toString()
    };

    // 입력 데이터를 JSON 파일로 저장
    fs.writeFileSync('./input.json', JSON.stringify(inputs, null, 2), 'utf8');
}

generateVC().then(() => {
    console.log('VC and inputs generated successfully.');
}).catch((error) => {
    console.error('Error generating VC and inputs:', error);
});
