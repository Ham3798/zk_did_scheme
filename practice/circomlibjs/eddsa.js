import { buildEddsa } from "circomlibjs";
import fs from 'fs'; // 파일 시스템 모듈 임포트

(async () => {
  // Eddsa 객체를 생성
  const eddsa = await buildEddsa();

  // 개인키 생성 (파일에서 읽기)
  const prvKey = fs.readFileSync('../private_key.pem');

  // 공개키 생성
  const pubKey = eddsa.prv2pub(prvKey);
  console.log("Public Key:", pubKey);

  // 서명할 메시지 (Uint8Array)
  const msg = Buffer.from("Hello, EdDSA!", "utf8");

  // Pedersen 해시를 사용한 서명 생성
  const signature = eddsa.signPedersen(prvKey, msg);
  console.log("Signature (R8, S):", signature);

  // 서명 검증
  const isValid = eddsa.verifyPedersen(msg, signature, pubKey);
  console.log("Is signature valid?", isValid);
})();
