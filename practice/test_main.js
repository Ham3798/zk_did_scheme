import { wasm } from "circom_tester";
import path from "path";
import { fileURLToPath } from 'url';
import * as chai from "chai";
import { newMemEmptyTrie, buildPoseidon, buildEddsa, buildBabyjub } from "circomlibjs";

const { assert, expect } = chai;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const totalLevels = 64;
const poseidon = await buildPoseidon();

describe("Main Circuit Test", function () {
    this.timeout(100000);

    it("Should test all functionalities in main.circom", async function () {
        // 서킷 로드
        const circuit = await wasm(path.join(__dirname, "./circuits/main.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });

        // 필요한 라이브러리 초기화
        const poseidon = await buildPoseidon();
        const eddsa = await buildEddsa();
        const babyJub = await buildBabyjub();
        const F = babyJub.F;

        // 예제 데이터 설정 (DID Document 등)
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

        // Create attribute keys mapping
        const attributes = didDocument.credentialSubject;
        const attributeKeys = {};
        let keyIndex = 0n;
        for (const key in attributes) {
        attributeKeys[key] = keyIndex++;
        }

        // Build the main SMT
        const tree = await newMemEmptyTrie();
        const Fr = tree.F;

        // Prepare the `alumniOf` SMT and its inclusion proofs
        const alumniAttributes = attributes.alumniOf;
        const alumniAttributeKeys = {};
        let alumniKeyIndex = 0;
        for (const key in alumniAttributes) {
            alumniAttributeKeys[key] = alumniKeyIndex++;
        }

        const alumniTree = await newMemEmptyTrie();

        // Insert alumni attributes into the alumniTree
        for (const [alumniKey, alumniValue] of Object.entries(alumniAttributes)) {
            console.log("(alumniKey, alumniValue) : ", alumniKey, alumniValue);
            if (typeof alumniValue === 'string') {
                const alumniValueBytes = Buffer.from(alumniValue, 'utf8');
                await alumniTree.insert(alumniAttributeKeys[alumniKey], Fr.e(poseidon([alumniValueBytes])));
                console.log("(alumniKey, alumniValue) : ", alumniAttributeKeys[alumniKey], Fr.e(poseidon([alumniValueBytes])))
            }
            else {
                await alumniTree.insert(alumniAttributeKeys[alumniKey], Fr.e(alumniValue));
                console.log("(alumniKey, alumniValue) : ", alumniAttributeKeys[alumniKey], Fr.e(alumniValue))
            }
        }

        const alumniTreeRoot = alumniTree.root;
        // Insert attributes into the main SMT
        for (const [key, value] of Object.entries(attributes)) {
            if (key === 'alumniOf') {
                await tree.insert(attributeKeys[key], alumniTreeRoot);
                console.log("(key, value) : ", attributeKeys[key], alumniTreeRoot)
            } else if (typeof value === 'string') {
                const valueBytes = Buffer.from(value, 'utf8');
                await tree.insert(attributeKeys[key], Fr.e(poseidon([valueBytes])));
                console.log("(key, value) : ", attributeKeys[key], Fr.e(poseidon([valueBytes])))
            } else {
                await tree.insert(attributeKeys[key], Fr.e(value));
                console.log("(key, value) : ", attributeKeys[key], Fr.e(value))
            }
        }

        console.log("Expected root:", tree.F.toObject(tree.root), tree.root);
        
        // SMT Inclusion 입력 준비
        // ... (SMT 관련 입력 준비 코드)
        const age_key = tree.F.e(attributeKeys['age']);
        const age_res = await tree.find(age_key);
        
        assert(age_res.found);
        let age_siblings = age_res.siblings;
        for (let i=0; i<age_siblings.length; i++) age_siblings[i] = tree.F.toObject(age_siblings[i]);
        while (age_siblings.length<totalLevels) age_siblings.push(0);

        const alumni_key = tree.F.e(attributeKeys['alumniOf']);
        const alumni_res = await tree.find(alumni_key);

        let alumni_siblings = alumni_res.siblings;
        for (let i=0; i<alumni_siblings.length; i++) alumni_siblings[i] = tree.F.toObject(alumni_siblings[i]);
        while (alumni_siblings.length<totalLevels) alumni_siblings.push(0);

        const university_key = tree.F.e(attributeKeys['name']);
        const university_res = await tree.find(university_key);

        assert(university_res.found);
        let university_siblings = university_res.siblings;
        for (let i=0; i<university_siblings.length; i++) university_siblings[i] = tree.F.toObject(university_siblings[i]);
        while (university_siblings.length<totalLevels) university_siblings.push(0);

        // EdDSA Verification 입력 준비
        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        const pubKey = eddsa.prv2pub(prvKey);
        const msg = F.e(tree.root);
        const signature = eddsa.signPoseidon(prvKey, msg);

        assert(eddsa.verifyPoseidon(msg, signature, pubKey));

        // 전체 입력 준비
        const input = {
            // 공통 루트 해시
            root: tree.F.toObject(tree.root),

            // 'age'에 대한 SMT 증명 입력
            enabled_age: 1,
            siblings_age: age_siblings,
            oldKey_age: 0,
            oldValue_age: 0,
            isOld0_age: 0,
            key_age: tree.F.toObject(age_key),
            value_age: tree.F.toObject(age_res.foundValue),
            fnc_age: 0,

            // 'alumniOf'에 대한 SMT 증명 입력
            enabled_alumni: 1,
            siblings_alumni: alumni_siblings,
            oldKey_alumni: 0,
            oldValue_alumni: 0,
            isOld0_alumni: 0,
            key_alumni: tree.F.toObject(alumni_key),
            value_alumni: tree.F.toObject(alumni_res.foundValue),
            fnc_alumni: 0,

            // 'name'에 대한 SMT 증명 입력
            enabled_name: 1,
            siblings_name: university_siblings,
            oldKey_name: 0,
            oldValue_name: 0,
            isOld0_name: 0,
            key_name: tree.F.toObject(university_key),
            value_name: tree.F.toObject(university_res.foundValue),
            fnc_name: 0,

            // EdDSA 서명 검증 입력
            enabled_eddsa: 1,
            Ax: F.toObject(pubKey[0]),
            Ay: F.toObject(pubKey[1]),
            R8x: F.toObject(signature.R8[0]),
            R8y: F.toObject(signature.R8[1]),
            S: signature.S,
            M: F.toObject(msg), // 루트 해시
        };
        
        console.log("input: ", input);
        // Witness 계산 및 검증
        const witness = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(witness);
    });
});

describe("SMTInclusion DID Circuit Test", function () {
    this.timeout(10000);

    it("should correctly verify SMT inclusion for the age attribute", async function () {
        // Load the SMTInclusionAge circuit
        const circuit = await wasm(path.join(__dirname, "./circuits/smt_inclusion.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });

        // Define the DID document with attributes
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

        // Create attribute keys mapping
        const attributes = didDocument.credentialSubject;
        const attributeKeys = {};
        let keyIndex = 0n;
        for (const key in attributes) {
        attributeKeys[key] = keyIndex++;
        }

        // Build the main SMT
        const tree = await newMemEmptyTrie();
        const Fr = tree.F;

        // Prepare the `alumniOf` SMT and its inclusion proofs
        const alumniAttributes = attributes.alumniOf;
        const alumniAttributeKeys = {};
        let alumniKeyIndex = 0;
        for (const key in alumniAttributes) {
            alumniAttributeKeys[key] = alumniKeyIndex++;
        }

        const alumniTree = await newMemEmptyTrie();

        // Insert alumni attributes into the alumniTree
        for (const [alumniKey, alumniValue] of Object.entries(alumniAttributes)) {
            console.log("(alumniKey, alumniValue) : ", alumniKey, alumniValue);
            if (typeof alumniValue === 'string') {
                const alumniValueBytes = Buffer.from(alumniValue, 'utf8');
                await alumniTree.insert(alumniAttributeKeys[alumniKey], Fr.e(poseidon([alumniValueBytes])));
                console.log("(alumniKey, alumniValue) : ", alumniAttributeKeys[alumniKey], Fr.e(poseidon([alumniValueBytes])))
            }
            else {
                await alumniTree.insert(alumniAttributeKeys[alumniKey], Fr.e(alumniValue));
                console.log("(alumniKey, alumniValue) : ", alumniAttributeKeys[alumniKey], Fr.e(alumniValue))
            }
        }

        const alumniTreeRoot = alumniTree.root;
        // Insert attributes into the main SMT
        for (const [key, value] of Object.entries(attributes)) {
            if (key === 'alumniOf') {
                await tree.insert(attributeKeys[key], alumniTreeRoot);
                console.log("(key, value) : ", attributeKeys[key], alumniTreeRoot)
            } else if (typeof value === 'string') {
                const valueBytes = Buffer.from(value, 'utf8');
                await tree.insert(attributeKeys[key], Fr.e(poseidon([valueBytes])));
                console.log("(key, value) : ", attributeKeys[key], Fr.e(poseidon([valueBytes])))
            } else {
                await tree.insert(attributeKeys[key], Fr.e(value));
                console.log("(key, value) : ", attributeKeys[key], Fr.e(value))
            }
        }

        console.log("Expected root:", tree.F.toObject(tree.root), tree.root);

        const age_key = tree.F.e(attributeKeys['age']);
        const age_res = await tree.find(age_key);
        
        assert(age_res.found);
        let age_siblings = age_res.siblings;
        for (let i=0; i<age_siblings.length; i++) age_siblings[i] = tree.F.toObject(age_siblings[i]);
        while (age_siblings.length<totalLevels) age_siblings.push(0);

        // Prepare inputs for the circuit
        const age_input = {
            enabled: 1,
            fnc: 0,
            root: tree.F.toObject(tree.root),
            siblings: age_siblings,
            oldKey: 0,
            oldValue: 0,
            isOld0: 0,
            key: tree.F.toObject(age_key),
            value: tree.F.toObject(age_res.foundValue)
        };

        // Debugging: print expected root and input
        // console.log("Expected root:", age_input.root);
        // console.log(age_input);

        // Calculate witness for the circuit
        const age_witness = await circuit.calculateWitness(age_input, true);

        // Debugging: print witness root
        // console.log("Witness root:", age_witness[1].toString());

        // Check circuit constraints
        await circuit.checkConstraints(age_witness);

        // Validate the SMT proof - expecting the output to be 1 (valid proof)
        assert.equal(age_witness[1].toString(), "1", "SMT inclusion for age failed");
        
        const alumni_key = tree.F.e(attributeKeys['alumniOf']);
        const alumni_res = await tree.find(alumni_key);

        assert(alumni_res.found);
        let alumni_siblings = alumni_res.siblings;
        for (let i=0; i<alumni_siblings.length; i++) alumni_siblings[i] = tree.F.toObject(alumni_siblings[i]);
        while (alumni_siblings.length<totalLevels) alumni_siblings.push(0);

        // Prepare inputs for the circuit
        const alumni_input = {
            enabled: 1,
            fnc: 0,
            root: tree.F.toObject(tree.root),
            siblings: alumni_siblings,
            oldKey: 0,
            oldValue: 0,
            isOld0: 0,
            key: tree.F.toObject(alumni_key),
            value: tree.F.toObject(alumni_res.foundValue)
        };

        // Debugging: print expected root and input
        // console.log("Expected root:", alumni_input.root);
        // console.log(alumni_input);

        // Calculate witness for the circuit
        const alumni_witness = await circuit.calculateWitness(alumni_input, true);

        // Debugging: print witness root
        // console.log("Witness root:", alumni_witness[1].toString());

        // Check circuit constraints
        await circuit.checkConstraints(alumni_witness);

        // Validate the SMT proof - expecting the output to be 1 (valid proof)
        assert.equal(alumni_witness[1].toString(), "1", "SMT inclusion for alumni failed");
        
        const university_key = tree.F.e(attributeKeys['name']);
        const university_res = await tree.find(university_key);

        assert(university_res.found);
        let university_siblings = university_res.siblings;
        for (let i=0; i<university_siblings.length; i++) university_siblings[i] = tree.F.toObject(university_siblings[i]);
        while (university_siblings.length<totalLevels) university_siblings.push(0);

        // Prepare inputs for the circuit
        const university_input = {
            enabled: 1,
            fnc: 0,
            root: tree.F.toObject(tree.root),
            siblings: university_siblings,
            oldKey: 0,
            oldValue: 0,
            isOld0: 0,
            key: tree.F.toObject(university_key),
            value: tree.F.toObject(university_res.foundValue)
        };

        // Debugging: print expected root and input
        // console.log("Expected root:", university_input.root);
        // console.log(university_input);

        // Calculate witness for the circuit
        const university_witness = await circuit.calculateWitness(university_input, true);

        // Debugging: print witness root
        // console.log("Witness root:", university_witness[1].toString());

        // Check circuit constraints
        await circuit.checkConstraints(university_witness);

        // Validate the SMT proof - expecting the output to be 1 (valid proof)
        assert.equal(university_witness[1].toString(), "1", "SMT inclusion for 'Chungnam National University' failed");
        

        const eddsa = await buildEddsa();
        const babyJub = await buildBabyjub();
        const F = babyJub.F;
        const eddsaCircuit = await wasm(path.join(__dirname, "./circuits/eddsa_verification.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });
        
        console.log(F.toObject(tree.root), tree.root, F.e(tree.root));

        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        const pubKey = eddsa.prv2pub(prvKey);
        const msg = F.e(tree.root);
        const signature = eddsa.signPoseidon(prvKey, msg);

        assert(eddsa.verifyPoseidon(msg, signature, pubKey));
        
        const input = {
            enabled: 1,
            Ax: F.toObject(pubKey[0]),
            Ay: F.toObject(pubKey[1]),
            R8x: F.toObject(signature.R8[0]),
            R8y: F.toObject(signature.R8[1]),
            S: signature.S,
            M: F.toObject(msg)
        };

        // console.log(JSON.stringify(utils.stringifyBigInts(input)));

        const w = await eddsaCircuit.calculateWitness(input, true);

        await eddsaCircuit.checkConstraints(w);

        const greaterthanCircuit = await wasm(path.join(__dirname, "./circuits/greaterthan.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });
        
        let witness = await greaterthanCircuit.calculateWitness({ "in": [25,tree.F.toObject(age_res.foundValue)] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        await greaterthanCircuit.checkConstraints(witness);
    });
});
