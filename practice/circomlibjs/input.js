const fs = require('fs');

// 경로 설정
const vcPath = './vc.json';
const inputJsonPath = './input.json';

// vc.json을 읽어서 input.json으로 변환하는 함수
function parseVC(vcData) {
    // 1. issuer 공개 키 추출
    const Ax = vcData.issuer.publicKey.Ax.split(',').map(Number);
    const Ay = vcData.issuer.publicKey.Ay.split(',').map(Number);

    // 2. 서명 정보 추출
    const R8x = vcData.proof.signature.R8x.split(',').map(Number);
    const R8y = vcData.proof.signature.R8y.split(',').map(Number);
    const S = BigInt(vcData.proof.signature.S);  // BigInt로 처리

    // 3. Merkle Root 추출
    const root = BigInt(vcData.proof.merkleRoot);

    // 4. 나이 및 자격 관련 정보 추출
    const age = Number(vcData.credentialSubject.age);

    // SMT 관련 키와 값은 가정된 값으로 설정
    const oldKey = age;  // 키로 나이를 가정
    const oldValue = age; // 기존 값도 나이로 가정
    const isOld0 = 0;  // 존재하는 항목으로 설정

    // siblings는 SMT 검증을 위한 Merkle 형제 노드, 여기서는 예시로 더미 데이터를 사용
    const siblings = Array(3).fill(0);

    // input.json 생성
    const inputJson = {
        root: root.toString(),
        siblings,
        oldKey,
        oldValue,
        isOld0,
        age,
        Ax,
        Ay,
        R8x,
        R8y,
        S: S.toString()
    };

    return inputJson;
}

// vc.json 파일을 읽고 input.json으로 변환 및 저장
fs.readFile(vcPath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading vc.json:', err);
        return;
    }

    const vcData = JSON.parse(data);
    const inputJson = parseVC(vcData);

    // input.json 파일로 저장
    fs.writeFile(inputJsonPath, JSON.stringify(inputJson, null, 2), (err) => {
        if (err) {
            console.error('Error writing input.json:', err);
        } else {
            console.log('input.json has been saved.');
        }
    });
});
