import { buildPoseidon, newMemEmptyTrie } from 'circomlibjs';

async function smtExample() {
    // Poseidon 해시 함수 초기화
    const poseidon = await buildPoseidon();

    // 속성 정의 (예시로 name, age, studentNumber)
    const attributes = {
        name: "ham3798",
        age: 25,
        studentNumber: "201902769"
    };

    // 속성의 고유한 키 인덱스 정의
    const attributeKeys = {};
    let keyIndex = 0n;
    for (const key in attributes) {
        if (key !== 'id') {
            attributeKeys[key] = keyIndex++;
        }
    }

    // circomlibjs의 Sparse Merkle Tree(SMT) 생성
    const tree = await newMemEmptyTrie();

    // 속성을 해시하고 SMT에 삽입
    for (const [key, value] of Object.entries(attributes)) {
        if (key !== 'id') {
            const keyBigInt = BigInt(attributeKeys[key]);
            let valueBigInt;
            if (typeof value === 'number') {
                valueBigInt = BigInt(value);
            } else {
                // 문자열을 BigInt로 변환
                const valueBuffer = Buffer.from(value.toString(), 'utf8');
                valueBigInt = BigInt('0x' + valueBuffer.toString('hex'));
            }
            // Poseidon을 사용하여 해시화
            const hashedValue = poseidon([valueBigInt]);
            await tree.insert(keyBigInt, hashedValue);
            console.log(`Inserted ${key}: ${hashedValue.toString()}`);
        }
    }

    // SMT의 Merkle 루트 계산
    const merkleRoot = tree.root;
    console.log("Merkle Root:", merkleRoot.toString());

    // 'age' 속성에 대한 Merkle 증명 생성
    const ageKey = BigInt(attributeKeys['age']);
    const { siblings, isOld0, value: oldValue } = await tree.find(ageKey);

    // Merkle 증명 출력
    console.log("Merkle Proof for 'age':");
    console.log("Siblings:", siblings.map(s => s.toString()));
    console.log("Is Old 0 (Key exists):", isOld0 ? "Yes" : "No");

    // 저장된 값 확인 (oldValue가 존재하지 않을 경우 처리)
    if (oldValue !== undefined) {
        console.log("Stored Value (Old):", oldValue.toString());
    } else {
        console.log("Stored Value (Old): None (Key was not present)");
    }
}

smtExample().then(() => {
    console.log('SMT 예제 완료');
}).catch((error) => {
    console.error('SMT 예제 실행 중 오류 발생:', error);
});
