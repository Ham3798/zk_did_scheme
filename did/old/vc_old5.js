import fs from 'fs';
import { buildEddsa, buildBabyjub, buildPoseidon, newMemEmptyTrie } from 'circomlibjs';

function arrayToHexString(arr) {
    return arr.map(x => x.toString(16).padStart(2, '0')).join('');
}

function bigintToUint8Array(bigint) {
    let hex = bigint.toString(16);
    if (hex.length % 2) {
        hex = '0' + hex;
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

function padSiblings(siblings, F) {
    const paddedSiblings = siblings.map(s => F.toObject(s));
    while (paddedSiblings.length < 64) {
        paddedSiblings.push(BigInt(0));
    }
    return paddedSiblings;
}

function uint8ArrayToHex(uint8Array) {
    return Array.from(uint8Array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateVC() {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const issuerPrivateKeyHex = fs.readFileSync('./private_key.pem', 'utf8').trim();
    const issuerPrivateKey = Buffer.from(issuerPrivateKeyHex, 'hex');

    const issuerPublicKey = eddsa.prv2pub(issuerPrivateKey);

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

    const attributes = didDocument.credentialSubject;
    const attributeKeys = {};
    let keyIndex = 0n;
    for (const key in attributes) {
        attributeKeys[key] = keyIndex++;
    }

    const tree = await newMemEmptyTrie();

    let alumniTreeRoot;
    let alumniAttributes;
    for (const [key, value] of Object.entries(attributes)) {
        const keyBigInt = BigInt(attributeKeys[key]);
        let storedValue;

        console.log("<Key, Value> : ", key, value);

        if (key === 'alumniOf') {
            const alumniTree = await newMemEmptyTrie();
            alumniAttributes = value;

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

                await alumniTree.insert(alumniKeyBigInt, alumniValueBigInt);

                console.log("Alumni SMT - KEY, VALUE: ", alumniKeyBigInt, alumniValueBigInt.toString());
            }

            alumniTreeRoot = alumniTree.root;
            storedValue = F.toObject(alumniTreeRoot);
            console.log("Alumni SMT Root: ", storedValue.toString());
        } else if (typeof value === 'number') {
            storedValue = BigInt(value);
        } else {
            const valueBuffer = Buffer.from(value.toString(), 'utf8');
            storedValue = BigInt('0x' + valueBuffer.toString('hex'));
        }

        await tree.insert(keyBigInt, storedValue);
        console.log("KEY, VALUE: ", keyBigInt.toString(), storedValue.toString());
    }

    const merkleRoot = tree.root;

    // 'age' 속성에 대한 Merkle 증명 생성
    const ageKey = BigInt(attributeKeys['age']);
    const ageValue = attributes['age'];
    const { siblings: ageSiblings, isOld0: isOld0Age, value: oldAgeValue } = await tree.find(ageKey);

    // 'alumniOf'에 대한 Merkle 증명 생성
    const alumniKey = BigInt(attributeKeys['alumniOf']);
    const { siblings: alumniSiblings, isOld0: isOld0Alumni, value: oldAlumniValue } = await tree.find(alumniKey);

    // SMT 깊이를 맞추기 위해 siblings 배열을 64개로 패딩
    const paddedAgeSiblings = padSiblings(ageSiblings, F);
    const paddedAlumniSiblings = padSiblings(alumniSiblings, F);

    // 'alumniOf.name' 속성에 대한 Merkle 증명 생성
    const alumniAttributesKeys = {};
    let alumniKeyIndex = 0n;
    for (const key in alumniAttributes) {
        alumniAttributesKeys[key] = alumniKeyIndex++;
    }

    const alumniNameKey = BigInt(alumniAttributesKeys['name']);
    const { siblings: alumniNameSiblings, isOld0: isOld0AlumniName, value: oldAlumniNameValue } = await (async () => {
        const alumniTree = await newMemEmptyTrie();
        for (const [alumniKey, alumniValue] of Object.entries(alumniAttributes)) {
            const alumniKeyBigInt = BigInt(alumniAttributesKeys[alumniKey]);
            let alumniValueBigInt;

            if (typeof alumniValue === 'string') {
                const alumniValueBuffer = Buffer.from(alumniValue, 'utf8');
                alumniValueBigInt = BigInt('0x' + alumniValueBuffer.toString('hex'));
            } else {
                alumniValueBigInt = BigInt(alumniValue);
            }

            await alumniTree.insert(alumniKeyBigInt, alumniValueBigInt);
        }

        return await alumniTree.find(alumniNameKey);
    })();

    const paddedAlumniNameSiblings = padSiblings(alumniNameSiblings, F);

    // Merkle 루트를 EdDSA로 서명
    const merkleRootField = F.toObject(merkleRoot);
    const merkleRootArray = bigintToUint8Array(merkleRootField);

    const signature = eddsa.signPoseidon(issuerPrivateKey, merkleRootArray);

    const Ax = BigInt('0x' + arrayToHexString(issuerPublicKey[0]));
    const Ay = BigInt('0x' + arrayToHexString(issuerPublicKey[1]));
    const R8x = BigInt('0x' + arrayToHexString(signature.R8[0]));
    const R8y = BigInt('0x' + arrayToHexString(signature.R8[1]));
    const S = signature.S.toString();

    const verifiableCredential = {
        ...didDocument,
        proof: {
            type: 'BabyJubJubPoseidonSignature2024',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: didDocument.issuer.id,
            merkleRoot: merkleRootField.toString(),
            signature: {
                R8x: R8x.toString(),
                R8y: R8y.toString(),
                S: S
            }
        },
        issuer: {
            ...didDocument.issuer,
            publicKey: {
                Ax: Ax.toString(),
                Ay: Ay.toString()
            }
        }
    };
    console.log("verifiableCredential: ", verifiableCredential)

    fs.writeFileSync('./vc.json', JSON.stringify(verifiableCredential, null, 2), 'utf8');

    const inputs = {
        root: merkleRootField.toString(),
        siblings: paddedAgeSiblings.map(s => s.toString()),
        alumniSiblings: paddedAlumniSiblings.map(s => s.toString()),
        oldKey: ageKey.toString(),
        oldValue: oldAgeValue ? oldAgeValue.toString() : '0',
        isOld0: isOld0Age ? 1 : 0,
        age: ageValue.toString(),
        alumniKey: alumniKey.toString(),
        alumniValue: oldAlumniValue ? oldAlumniValue.toString() : '0',
        isAlumniOld0: isOld0Alumni ? 1 : 0,
        alumniTreeSiblings: paddedAlumniNameSiblings.map(s => s.toString()),
        alumniNameKey: alumniNameKey.toString(),
        alumniNameValue: oldAlumniNameValue ? oldAlumniNameValue.toString() : '0',
        isAlumniNameOld0: isOld0AlumniName ? 1 : 0,
        Ax: Ax.toString(),
        Ay: Ay.toString(),
        R8x: R8x.toString(),
        R8y: R8y.toString(),
        S: S
    };
    console.log("inputs: ", inputs)

    fs.writeFileSync('./input.json', JSON.stringify(inputs, null, 2), 'utf8');
}

generateVC().then(() => {
    console.log('VC and inputs generated successfully.');
}).catch((error) => {
    console.error('Error generating VC and inputs:', error);
});
