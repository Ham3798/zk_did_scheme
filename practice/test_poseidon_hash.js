import * as chai from "chai";
import path from "path";
import { fileURLToPath } from 'url';
import { wasm } from "circom_tester";
import { buildPoseidon } from "circomlibjs";

const assert = chai.assert;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("Poseidon Circuit test for Chungnam National University", function () {
    let poseidon;
    let F;
    let circuit;
    
    this.timeout(1000000);

    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
        // Load the circuit for testing Poseidon hash
        circuit = await wasm(path.join(__dirname, "./circuits/poseidon_hash.circom"), {
            include: [path.join(__dirname, "../node_modules/circomlib/circuits")]
        });
    });
    
    it("Should check Poseidon hash for 'Chungnam National University'", async () => {
        // Convert the string 'Chungnam National University' to BigInt
        const universityString = "Chungnam National University";
        const universityBytes = Buffer.from(universityString, 'utf8');
        const universityBigInt = BigInt('0x' + universityBytes.toString('hex'));
        
        console.log("universityBytes", universityBytes);
        console.log("universityBytes_length", universityBytes.length);
        console.log("universityBigInt", [universityBigInt]);
        
        // Calculate Poseidon hash for the input
        const resPoseidon = poseidon([universityBigInt]);
        
        // Generate the witness for the circuit
        const w = await circuit.calculateWitness({ inputs: [universityBigInt] }, true);
        
        // Compare the expected hash with the circuit's output
        await circuit.assertOut(w, { out: F.toObject(resPoseidon) });
        await circuit.checkConstraints(w);
        
        // Verify the Poseidon hash value
        console.log("Poseidon hash for 'Chungnam National University':", resPoseidon.toS);
        assert(F.eq(F.e(resPoseidon), F.e(w[1])));
    });
});
