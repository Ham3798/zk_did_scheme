pragma circom 2.0.0;

include "./smt/smtverifier.circom";
include "./eddsaposeidon.circom";
include "./comparators.circom";

// 메인 서킷: 모든 SMT 증명, 서명 검증, 나이 검증 포함
template MainCircuit(nLevels) {
    // 공통 루트 해시 (모든 SMT 증명에서 사용)
    signal input root;

    // SMT Inclusion Components for 'age'
    signal input enabled_age;
    signal input siblings_age[nLevels];
    signal input oldKey_age;
    signal input oldValue_age;
    signal input isOld0_age;
    signal input key_age;
    signal input value_age;
    signal input fnc_age;

    component smtVerifierAge = SMTVerifier(nLevels);
    smtVerifierAge.enabled <== enabled_age;
    smtVerifierAge.root <== root;
    smtVerifierAge.siblings <== siblings_age;
    smtVerifierAge.oldKey <== oldKey_age;
    smtVerifierAge.oldValue <== oldValue_age;
    smtVerifierAge.isOld0 <== isOld0_age;
    smtVerifierAge.key <== key_age;
    smtVerifierAge.value <== value_age;
    smtVerifierAge.fnc <== fnc_age;

    // SMT Inclusion Components for 'alumniOf'
    signal input enabled_alumni;
    signal input siblings_alumni[nLevels];
    signal input oldKey_alumni;
    signal input oldValue_alumni;
    signal input isOld0_alumni;
    signal input key_alumni;
    signal input value_alumni;
    signal input fnc_alumni;

    component smtVerifierAlumni = SMTVerifier(nLevels);
    smtVerifierAlumni.enabled <== enabled_alumni;
    smtVerifierAlumni.root <== root;
    smtVerifierAlumni.siblings <== siblings_alumni;
    smtVerifierAlumni.oldKey <== oldKey_alumni;
    smtVerifierAlumni.oldValue <== oldValue_alumni;
    smtVerifierAlumni.isOld0 <== isOld0_alumni;
    smtVerifierAlumni.key <== key_alumni;
    smtVerifierAlumni.value <== value_alumni;
    smtVerifierAlumni.fnc <== fnc_alumni;

    // SMT Inclusion Components for 'name'
    signal input enabled_name;
    signal input siblings_name[nLevels];
    signal input oldKey_name;
    signal input oldValue_name;
    signal input isOld0_name;
    signal input key_name;
    signal input value_name;
    signal input fnc_name;

    component smtVerifierName = SMTVerifier(nLevels);
    smtVerifierName.enabled <== enabled_name;
    smtVerifierName.root <== root;
    smtVerifierName.siblings <== siblings_name;
    smtVerifierName.oldKey <== oldKey_name;
    smtVerifierName.oldValue <== oldValue_name;
    smtVerifierName.isOld0 <== isOld0_name;
    smtVerifierName.key <== key_name;
    smtVerifierName.value <== value_name;
    smtVerifierName.fnc <== fnc_name;

    // EdDSA Verification Component
    signal input enabled_eddsa;
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input M; // 루트 해시를 메시지로 사용

    component eddsaVerifier = EdDSAPoseidonVerifier();
    eddsaVerifier.enabled <== enabled_eddsa;
    eddsaVerifier.Ax <== Ax;
    eddsaVerifier.Ay <== Ay;
    eddsaVerifier.R8x <== R8x;
    eddsaVerifier.R8y <== R8y;
    eddsaVerifier.S <== S;
    eddsaVerifier.M <== M;

    component ageCheck = GreaterEqThan(32);
    ageCheck.in[0] <== value_age; // SMT 증명에서 얻은 나이 값
    ageCheck.in[1] <== 25;
    ageCheck.out === 1;
}

component main = MainCircuit(64);
