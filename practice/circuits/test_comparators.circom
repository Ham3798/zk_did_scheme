pragma circom 2.0.0;

include "./comparators.circom";

template Comparators() {
    signal input age;               // 입력: 나이
    signal input universityNameValue;   // 입력: 소속 (예: 해시된 학교 이름)
    signal output isAgeValid;       // 나이 검증 결과
    signal output isAlumniValid;    // 소속 검증 결과

    var expectedUniversityNameValue = 7098895365052177069940869631875988722267756123006876516876982776953; // "Chungnam National University" 해시 값

    // 나이가 25 이상인지 확인 (age >= 25)
    component ageCheck = GreaterEqThan(32);  // 나이 값이 32비트라고 가정
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== 25;
    ageCheck.out === 1;

    // 소속 이름이 "Chungnam National University"인지 확인
    component alumniNameCheck = IsEqual();
    alumniNameCheck.in[0] <== universityNameValue;
    alumniNameCheck.in[1] <== expectedUniversityNameValue;
    alumniNameCheck.out === 1;
}

component main = Comparators();
