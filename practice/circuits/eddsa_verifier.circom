pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

template EdDSAVerifier() {
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input M; // Merkle Root as the message

    component eddsaVerifier = EdDSAPoseidonVerifier();
    eddsaVerifier.enabled <== 1;
    eddsaVerifier.Ax <== Ax;
    eddsaVerifier.Ay <== Ay;
    eddsaVerifier.R8x <== R8x;
    eddsaVerifier.R8y <== R8y;
    eddsaVerifier.S <== S;
    eddsaVerifier.M <== M;
}

component main = EdDSAVerifier();
