import { wasm } from "circom_tester";
import path from "path";
import { fileURLToPath } from 'url';
import * as chai from "chai";
import { newMemEmptyTrie, buildPoseidon } from "circomlibjs";

const { assert, expect } = chai;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const totalLevels = 64;
const poseidon = await buildPoseidon();

async function testInclusion(tree, _key, circuit) {
    const key = tree.F.e(_key);
    const res = await tree.find(key);

    assert(res.found);
    let siblings = res.siblings;
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<totalLevels) siblings.push(0);

    const w = await circuit.calculateWitness({
        enabled: 1,
        root: tree.F.toObject(tree.root),
        siblings: siblings,
        oldKey: 0,
        oldValue: 0,
        isOld0: 0,
        key: tree.F.toObject(key),
        value: tree.F.toObject(res.foundValue),
        fnc: 0
    }, true);

    await circuit.checkConstraints(w);

}

async function testExclusion(tree, _key, circuit) {
    const key = tree.F.e(_key);
    const res = await tree.find(key);

    assert(!res.found);
    let siblings = res.siblings;
    for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
    while (siblings.length<totalLevels) siblings.push(0);

    const w = await circuit.calculateWitness({
        enabled: 1,
        root: tree.F.toObject(tree.root),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey),
        oldValue: res.isOld0 ? 0 : tree.F.toObject(res.notFoundValue),
        isOld0: res.isOld0 ? 1 : 0,
        key: tree.F.toObject(key),
        value: 0,
        fnc: 1
    });

    const input = {
        enabled: 1,
        root: tree.F.toObject(tree.root),
        siblings: siblings,
        oldKey: res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey),
        oldValue: res.isOld0 ? 0 : tree.F.toObject(res.notFoundValue),
        isOld0: res.isOld0 ? 1 : 0,
        key: tree.F.toObject(key),
        value: 0,
        fnc: 1
    }
    console.log("input: ", input);

    await circuit.checkConstraints(w);

}


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

        // Compute the Merkle root
        const merkleRoot = tree.root;

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
        console.log("Expected root:", age_input.root);
        // console.log(age_input);

        // Calculate witness for the circuit
        const age_witness = await circuit.calculateWitness(age_input, true);

        // Debugging: print witness root
        console.log("Witness root:", age_witness[1].toString());

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
        console.log("Expected root:", alumni_input.root);
        // console.log(alumni_input);

        // Calculate witness for the circuit
        const alumni_witness = await circuit.calculateWitness(alumni_input, true);

        // Debugging: print witness root
        console.log("Witness root:", alumni_witness[1].toString());

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
        console.log("Expected root:", university_input.root);
        // console.log(university_input);

        // Calculate witness for the circuit
        const university_witness = await circuit.calculateWitness(university_input, true);

        // Debugging: print witness root
        console.log("Witness root:", university_witness[1].toString());

        // Check circuit constraints
        await circuit.checkConstraints(university_witness);

        // Validate the SMT proof - expecting the output to be 1 (valid proof)
        assert.equal(university_witness[1].toString(), "1", "SMT inclusion for 'Chungnam National University' failed");
    });
});




describe("SMTInclusionAge Circuit Test", function () {
    this.timeout(10000);

    it("should correctly verify SMT inclusion for the age attribute", async function () {
        // Load the SMTInclusionAge circuit
        const circuit = await wasm(path.join(__dirname, "./circuits/smt_inclusion.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });

        // Initialize SMT
        let tree = await newMemEmptyTrie();

        const ageKey = 1; // Let's assume key 0 represents 'age'
        const ageValue = 25; // Save the age value directly

        const alumniKey = 2; // Key for 'alumniOf'
        const alumniValue = ""; // Value for alumniOf

        // Insert the age value directly into the SMT (no Poseidon hash)
        await tree.insert(ageKey, ageValue);
        await tree.insert(alumniKey, alumniValue);

        const key = tree.F.e(ageKey);
        const res = await tree.find(key);
        
        assert(res.found);
        let siblings = res.siblings;
        for (let i=0; i<siblings.length; i++) siblings[i] = tree.F.toObject(siblings[i]);
        while (siblings.length<totalLevels) siblings.push(0);

        // Prepare inputs for the circuit
        const input = {
            enabled: 1,
            fnc: 0,
            root: tree.F.toObject(tree.root),
            siblings: siblings,
            oldKey: 0,
            oldValue: 0,
            isOld0: 0,
            key: tree.F.toObject(key),
            value: tree.F.toObject(res.foundValue)
        };

        // Debugging: print expected root and input
        console.log("Expected root:", input.root);
        console.log(input);

        // Calculate witness for the circuit
        const witness = await circuit.calculateWitness(input, true);

        // Debugging: print witness root
        console.log("Witness root:", witness[1].toString());

        // Check circuit constraints
        await circuit.checkConstraints(witness);

        // Validate the SMT proof - expecting the output to be 1 (valid proof)
        assert.equal(witness[1].toString(), "1", "SMT inclusion for age failed");
    });

});

describe("SMT Verifier test", function () {
    let Fr;
    let circuit;
    let tree;

    this.timeout(100000);

    before( async () => {
        circuit = await wasm(path.join(__dirname, "./circuits/smt_inclusion.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });

        tree = await newMemEmptyTrie();
        Fr = tree.F;
        await tree.insert(7,77);
        await tree.insert(8,88);
        await tree.insert(32,3232);
    });

    it("Check inclussion in a tree of 3", async () => {
        await testInclusion(tree, 7, circuit);
        await testInclusion(tree, 8, circuit);
        await testInclusion(tree, 32, circuit);
    });

    it("Check exclussion in a tree of 3", async () => {
        await testExclusion(tree, 0, circuit);
        await testExclusion(tree, 6, circuit);
        await testExclusion(tree, 9, circuit);
        await testExclusion(tree, 33, circuit);
        await testExclusion(tree, 31, circuit);
        await testExclusion(tree, 16, circuit);
        await testExclusion(tree, 64, circuit);
    });

    it("Check not enabled accepts any thing", async () => {
        let siblings = [];
        for (let i=0; i<totalLevels; i++) siblings.push(i);

        const w = await circuit.calculateWitness({
            enabled: 0,
            fnc: 0,
            root: 1,
            siblings: siblings,
            oldKey: 22,
            oldValue: 33,
            isOld0: 0,
            key: 44,
            value: 0
        });


        await circuit.checkConstraints(w);
    });

    it("Check inclussion Adria case", async () => {
        const e1_hi= Fr.e("17124152697573569611556136390143205198134245887034837071647643529178599000839");
        const e1_hv= Fr.e("19650379996168153643111744440707177573540245771926102415571667548153444658179");

        const e2ok_hi= Fr.e("16498254692537945203721083102154618658340563351558973077349594629411025251262");
        const e2ok_hv= Fr.e("19650379996168153643111744440707177573540245771926102415571667548153444658179");

        const e2fail_hi= Fr.e("17195092312975762537892237130737365903429674363577646686847513978084990105579");
        const e2fail_hv= Fr.e("19650379996168153643111744440707177573540245771926102415571667548153444658179");

        const tree1 = await newMemEmptyTrie();
        await tree1.insert(e1_hi,e1_hv);
        await tree1.insert(e2ok_hi,e2ok_hv);

        await testInclusion(tree1, e2ok_hi, circuit);

        const tree2 = await newMemEmptyTrie();
        await tree2.insert(e1_hi,e1_hv);
        await tree2.insert(e2fail_hi,e2fail_hv);

        await testInclusion(tree2, e2fail_hi, circuit);
    });
});
