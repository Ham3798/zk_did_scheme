import { F1Field, Scalar } from "ffjavascript";
import { wasm } from "circom_tester";
import path from "path";
import { fileURLToPath } from 'url';
import * as chai from "chai";
import { newMemEmptyTrie } from "circomlibjs";

const assert = chai.assert;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const Fr = new F1Field(p);

describe("Comparators test", function ()  {
    this.timeout(100000);

    it("Should create a comparison greaterthan", async() => {
        const circuit = await wasm(path.join(__dirname, "./circuits/greaterthan.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });
        
        let witness;
        witness = await circuit.calculateWitness({ "in": [333,444] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        witness = await circuit.calculateWitness({ "in":[1,1] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        witness = await circuit.calculateWitness({ "in": [661, 660] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

        witness = await circuit.calculateWitness({ "in": [0, 1] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        witness = await circuit.calculateWitness({ "in": [0, 444] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        witness = await circuit.calculateWitness({ "in": [1, 0] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

        witness = await circuit.calculateWitness({ "in": [555, 0] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

        witness = await circuit.calculateWitness({ "in": [0, 0] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

        witness = await circuit.calculateWitness({ "in": [25, 30] }, true);
        assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
        assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));
    });
});

it("Should create a isequal circuit", async() => {
    const circuit = await wasm(path.join(__dirname, "./circuits/isequal.circom"), {
        include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
    });

    let witness;
    witness = await circuit.calculateWitness({ "in": [111,222] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));


    witness = await circuit.calculateWitness({ "in": [444,444] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));
});
it("Should create a comparison lessthan", async() => {
    const circuit = await wasm(path.join(__dirname, "./circuits/lessthan.circom"), {
        include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
    });

    let witness;
    witness = await circuit.calculateWitness({ "in": [333,444] }), true;
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

    witness = await circuit.calculateWitness({ "in":[1,1] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

    witness = await circuit.calculateWitness({ "in": [661, 660] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

    witness = await circuit.calculateWitness({ "in": [0, 1] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

    witness = await circuit.calculateWitness({ "in": [0, 444] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(1)));

    witness = await circuit.calculateWitness({ "in": [1, 0] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

    witness = await circuit.calculateWitness({ "in": [555, 0] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));

    witness = await circuit.calculateWitness({ "in": [0, 0] }, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
    assert(Fr.eq(Fr.e(witness[1]), Fr.e(0)));
});

// Comparators circuit test (age check and alumni name check)
it("Should create a comparators circuit for age and alumni name", async() => {
    const circuit = await wasm(path.join(__dirname, "./circuits/test_comparators.circom"), {
        include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
    });

    const expectedAlumniNameValue = BigInt("7098895365052177069940869631875988722267756123006876516876982776953"); // "Chungnam National University" hashed
    
    // Test case 1: Age 25 and correct alumni name
    let witness = await circuit.calculateWitness({
        age: 25,
        alumniNameValue: expectedAlumniNameValue
    }, true);
    console.log("witness:", witness);

    circuit.checkConstraints(witness);
});