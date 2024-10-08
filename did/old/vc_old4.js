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

// 64개로 패딩하는 함수 추가
function padSiblings(siblings, F) {
    const paddedSiblings = siblings.map(s => F.toObject(s));
    while (paddedSiblings.length < 64) {
        paddedSiblings.push(BigInt(0));  // 64개가 될 때까지 0으로 패딩
    }
    return paddedSiblings;
}

// Uint8Array를 16진수 문자열로 변환하는 함수 추가
function uint8ArrayToHex(uint8Array) {
    return Array.from(uint8Array).map(b => b.toString(16).padStart(2, '0')).join('');
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
        // 'id'도 포함하도록 수정
        attributeKeys[key] = keyIndex++;
    }

    // circomlibjs를 사용한 Sparse Merkle Tree(SMT) 생성
    const tree = await newMemEmptyTrie();

    // 속성을 해싱하고 SMT에 삽입
    for (const [key, value] of Object.entries(attributes)) {
        const keyBigInt = BigInt(attributeKeys[key]);
        let hashedValue;  // 'hashedValue' 변수를 블록 밖에서 선언
        console.log("<Key, Value> : ", key, value);
        if (key === 'alumniOf') {
            // alumniOf를 위한 별도의 SMT 생성
            const alumniTree = await newMemEmptyTrie();
            const alumniAttributes = value; // alumniOf의 내부 속성들

            // alumniOf 내부 속성을 해싱하여 SMT에 삽입
            for (const [alumniKey, alumniValue] of Object.entries(alumniAttributes)) {
                console.log("<alumniKey, alumniValue> : ", alumniKey, alumniValue);
                const alumniKeyBigInt = BigInt(Object.keys(alumniAttributes).indexOf(alumniKey));
                let alumniValueBigInt;

                if (typeof alumniValue === 'string') {
                    const alumniValueBuffer = Buffer.from(alumniValue, 'utf8');
                    alumniValueBigInt = BigInt('0x' + alumniValueBuffer.toString('hex'));
                } else {
                    alumniValueBigInt = BigInt(alumniValue);
                }

                // Poseidon 해시 사용하여 alumniOf의 각 속성 해싱
                const alumniHashedValue = poseidon([alumniValueBigInt]);
                await alumniTree.insert(alumniKeyBigInt, alumniHashedValue);

                console.log("Alumni SMT - KEY, VALUE, HASH : ", alumniKeyBigInt, alumniValueBigInt, uint8ArrayToHex(alumniHashedValue));
            }

            // alumniOf SMT의 루트 해시를 value로 설정
            const alumniRoot = alumniTree.root;
            hashedValue = poseidon([F.toObject(alumniRoot)]);  // 'hashedValue'를 여기에 초기화
            console.log("Alumni SMT Root: ", uint8ArrayToHex(alumniRoot));

        } else if (typeof value === 'number') {
            hashedValue = poseidon([BigInt(value)]);  // 숫자형 값을 해싱
        } else {
            // 문자열을 처리 (예: id 포함)
            const valueBuffer = Buffer.from(value.toString(), 'utf8');
            const valueBigInt = BigInt('0x' + valueBuffer.toString('hex'));  // 문자열을 16진수로 변환
            hashedValue = poseidon([valueBigInt]);  // 문자열 값을 해싱
        }

        // 기본 SMT에 key와 hashed value 삽입
        await tree.insert(keyBigInt, hashedValue);  // 'hashedValue'를 사용
        console.log("KEY, VALUE, HASH : ", keyBigInt, value, uint8ArrayToHex(hashedValue));
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

    // SMT 깊이를 맞추기 위해 siblings 배열을 64개로 패딩
    const paddedAgeSiblings = padSiblings(ageSiblings, F);
    const paddedAlumniSiblings = padSiblings(alumniSiblings, F);

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
        root: merkleRootField.toString(),
        siblings: paddedAgeSiblings.map(s => s.toString()),  // 패딩된 siblings 사용
        alumniSiblings: paddedAlumniSiblings.map(s => s.toString()),  // 패딩된 alumniSiblings 사용
        oldKey: ageKey.toString(),
        oldValue: oldAgeValue ? oldAgeValue.toString() : '0',
        isOld0: isOld0Age ? 1 : 0,
        alumniKey: alumniKey.toString(),
        alumniValue: oldAlumniValue ? oldAlumniValue.toString() : '0',
        isAlumniOld0: isOld0Alumni ? 1 : 0,
        age: ageValue.toString(),
        Ax: uint8ArrayToHex(issuerPublicKey[0]),
        Ay: uint8ArrayToHex(issuerPublicKey[1]),
        R8x: uint8ArrayToHex(signature.R8[0]),
        R8y: uint8ArrayToHex(signature.R8[1]),
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
