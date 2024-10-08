pragma circom 2.0.0;

include "./smt/smtverifier.circom";

template SMTInclusionAge(nLevels) {
    signal input enabled;
    signal input root;
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input key;
    signal input value;
    signal input fnc;
    
    component smtVerifierAge = SMTVerifier(nLevels);
    smtVerifierAge.enabled <== enabled;
    smtVerifierAge.root <== root;
    smtVerifierAge.siblings <== siblings;
    smtVerifierAge.oldKey <== oldKey;
    smtVerifierAge.oldValue <== oldValue;
    smtVerifierAge.isOld0 <== isOld0;
    smtVerifierAge.key <== key;
    smtVerifierAge.value <== value;
    smtVerifierAge.fnc <== fnc;
}

component main = SMTInclusionAge(64);
