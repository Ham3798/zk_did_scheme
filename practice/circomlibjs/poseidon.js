import { buildPoseidon, buildBabyjub } from "circomlibjs";
import { Scalar } from "ffjavascript";

(async () => {
  // BabyJub 및 Poseidon 해시 빌드
  const babyJub = await buildBabyjub();
  const poseidon = await buildPoseidon();

  // 메시지 예시 (Uint8Array 형태로 변환)
  const msg = Buffer.from("Chungnam National University", "utf8");

  // 메시지를 Poseidon 해시로 처리
  const hashInputs = Array.from(msg).map(byte => Scalar.e(byte)); // msg를 Scalar로 변환
  const hash = poseidon(hashInputs); // Poseidon 해시 수행

  console.log("Poseidon Hash of Message:", hash);
})();
