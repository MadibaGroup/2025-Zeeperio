// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BN254.sol";

contract ZeeperioBN254Verifier {
    using BN254 for BN254.G1Point;

    uint256 internal constant FR_MOD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 internal constant FQ_MOD = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 internal constant GENERATOR = 5;

    uint16 internal constant LABEL_A = 0;
    uint16 internal constant LABEL_M = 1;
    uint16 internal constant LABEL_SBLK_A = 2;
    uint16 internal constant LABEL_SBLK_M = 3;
    uint16 internal constant LABEL_ACC_A = 4;
    uint16 internal constant LABEL_ACC_M = 5;
    uint16 internal constant LABEL_TALLY_ACC = 6;
    uint16 internal constant LABEL_ZPAD = 7;
    uint16 internal constant LABEL_SEL_BLK_A = 8;
    uint16 internal constant LABEL_Z1A = 9;
    uint16 internal constant LABEL_Z2A = 10;
    uint16 internal constant LABEL_Z3A = 11;
    uint16 internal constant LABEL_Z1M = 12;
    uint16 internal constant LABEL_Z2M = 13;
    uint16 internal constant LABEL_Z3M = 14;
    uint16 internal constant LABEL_TAIL_KEEP = 15;
    uint16 internal constant LABEL_TAIL_SKIP = 16;
    uint16 internal constant LABEL_Q = 17;
    uint16 internal constant LABEL_CAND_BASE = 1000;

    uint16 internal constant LABEL_BID = 200;
    uint16 internal constant LABEL_CCONFIRM = 201;
    uint16 internal constant LABEL_M_INCL = 202;
    uint16 internal constant LABEL_BID_SH = 203;
    uint16 internal constant LABEL_CCONFIRM_SH = 204;
    uint16 internal constant LABEL_M_SH = 205;
    uint16 internal constant LABEL_T = 206;
    uint16 internal constant LABEL_TPRIME = 207;
    uint16 internal constant LABEL_T1 = 208;
    uint16 internal constant LABEL_T2 = 209;
    uint16 internal constant LABEL_ACCT1 = 210;
    uint16 internal constant LABEL_ACCT2 = 211;
    uint16 internal constant LABEL_Q_INCL = 212;

    uint16 internal constant LABEL_CCONFIRM_RECEIPT = 301;
    uint16 internal constant LABEL_D = 300;
    uint16 internal constant LABEL_SEL = 302;
    uint16 internal constant LABEL_ACC_SEL = 303;
    uint16 internal constant LABEL_Q_RECEIPT = 304;

    uint8 internal constant KIND_MAIN = 0;
    uint8 internal constant KIND_INCLUSION = 1;
    uint8 internal constant KIND_RECEIPT = 2;

    error InvalidProof(uint8 kind);
    error ProofKindMismatch(uint8 expected, uint8 received);

    event Verified(uint8 indexed kind, bytes32 indexed proofId, address indexed caller);

    BN254.G1Point public vk_g = BN254.G1Point(
        0x0000000000000000000000000000000000000000000000000000000000000001,
        0x0000000000000000000000000000000000000000000000000000000000000002
    );

    BN254.G1Point public vk_gamma_g = BN254.G1Point(
        0x2aec849043ce72af8d154ba041eddff3864e1e9eecf7fef6f6e6431b410d95df,
        0x0a751d719df38ffce003644bb2506daee399b2d8b431db2496c71cf3c3357d9d
    );

    BN254.G2Point internal vk_h = BN254.G2Point(
        [
            uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
            uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
        ],
        [
            uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
            uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
        ]
    );

    BN254.G2Point internal vk_beta_h = BN254.G2Point(
        [
            uint256(0x139673d1a8505b239ff3cfe750a3725a317e1b98ab5153b2714bca1ab06f7a3c),
            uint256(0x0121b5ae2921a8733fd4b9a0254fc4417a306486f64692c64f34f8e55c75a03b)
        ],
        [
            uint256(0x1e987b6d8857fc8865d6721eccfb7f0fd8131f42a95bd22ab89e1e6328e3ac42),
            uint256(0x0858eb6247ffef64b34d583daa3c82da600e27ba3708293cfce3c3409740c174)
        ]
    );

    struct Commitment {
        uint16 label;
        BN254.G1Point point;
    }

    struct Opening {
        BN254.G1Point witness;
        uint256 point;
        uint256 gamma;
        uint16[] labels;
        uint256[] values;
        uint256[] blindings;
    }

    struct PublicInputs {
        uint256 n;
        uint256 candidates;
        uint256 sumABallots;
        uint256 sumM;
        uint256[] tally;
        uint256 disputedCode;
        uint256 ballotIndex;
    }

    struct Proof {
        uint8 kind;
        Commitment[] commitments;
        Opening[] openings;
        PublicInputs publicInputs;
        uint256 alpha;
        uint256 beta;
        uint256 zeta;
        uint256 r;
    }

    struct EvalCache {
        uint256 a;
        uint256 m;
        uint256 sblkA;
        uint256 sblkM;
        uint256 accA;
        uint256 accM;
        uint256 tallyAcc;
        uint256 accAShift;
        uint256 accMShift;
        uint256 tallyShift;
        uint256 zPad;
        uint256 selBlkA;
        uint256 z1a;
        uint256 z2a;
        uint256 z3a;
        uint256 z1m;
        uint256 z2m;
        uint256 z3m;
        uint256 tailKeep;
        uint256 tailSkip;
    }

    function verifyMain(bytes calldata proofCalldata) external returns (bool) {
        return _verify(KIND_MAIN, proofCalldata);
    }

    function verifyInclusion(bytes calldata proofCalldata) external returns (bool) {
        return _verify(KIND_INCLUSION, proofCalldata);
    }

    function verifyReceipt(bytes calldata proofCalldata) external returns (bool) {
        return _verify(KIND_RECEIPT, proofCalldata);
    }

    function _verify(uint8 expectedKind, bytes calldata proofCalldata) internal returns (bool) {
        Proof memory proof = abi.decode(proofCalldata, (Proof));
        if (proof.kind != expectedKind) {
            revert ProofKindMismatch(expectedKind, proof.kind);
        }

        proof.kind = expectedKind;
        if (!verify(proof)) {
            revert InvalidProof(expectedKind);
        }
        emit Verified(expectedKind, keccak256(proofCalldata), msg.sender);
        return true;
    }

    function verify(Proof memory proof) public view returns (bool) {
        if (proof.publicInputs.n == 0 || proof.publicInputs.tally.length != proof.publicInputs.candidates) {
            return false;
        }

        (uint256 alpha, uint256 beta, uint256 zeta, uint256 rFs) = computeTranscript(proof);
        if (alpha != proof.alpha % FR_MOD || zeta != proof.zeta % FR_MOD) {
            return false;
        }
        if (proof.kind == KIND_INCLUSION && beta != proof.beta % FR_MOD) {
            return false;
        }

        uint256 r = deriveR(proof.openings);
        if (r != proof.r % FR_MOD) {
            return false;
        }

        if (!pairingCheck(proof)) {
            return false;
        }

        uint256 omega = rootOfUnity(proof.publicInputs.n);
        if (proof.kind == KIND_MAIN) {
            (bool ok, uint256 pvanish, uint256 qZeta) =
                constraintsAtZetaMain(alpha, zeta, omega, proof.publicInputs, proof.openings);
            if (!ok) return false;
            uint256 zh = subMod(powMod(zeta, proof.publicInputs.n), 1);
            return pvanish == mulmod(qZeta, zh, FR_MOD);
        } else if (proof.kind == KIND_INCLUSION) {
            (bool ok, uint256 pvanish, uint256 qZeta, uint256 zh) =
                constraintsAtZetaInclusion(alpha, beta, zeta, rFs, omega, proof.publicInputs, proof.openings);
            if (!ok) return false;
            return pvanish == mulmod(qZeta, zh, FR_MOD);
        } else {
            (bool ok, uint256 pvanish, uint256 qZeta, uint256 zh, uint256 receiptEq) =
                constraintsAtZetaReceipt(alpha, zeta, omega, proof.publicInputs, proof.openings);
            if (!ok) return false;
            if (receiptEq != 0) return false;
            return pvanish == mulmod(qZeta, zh, FR_MOD);
        }
    }

    function pairingCheck(Proof memory proof) internal view returns (bool) {
        for (uint256 i = 0; i < proof.openings.length; i++) {
            Opening memory opening = proof.openings[i];
            (BN254.G1Point memory sumCm, uint256 sumValue, uint256 sumBlinding, bool ok) =
                combineOpening(opening, proof.commitments);
            if (!ok) {
                return false;
            }

            BN254.G1Point memory sumCommittedEval =
                BN254.add(BN254.mul(vk_g, sumValue), BN254.mul(vk_gamma_g, sumBlinding));

            BN254.G1Point memory left = BN254.add(sumCm, BN254.negate(sumCommittedEval));
            left = BN254.add(left, BN254.mul(opening.witness, opening.point % FR_MOD));

            if (!BN254.pairingProd2(left, vk_h, BN254.negate(opening.witness), vk_beta_h)) {
                return false;
            }
        }
        return true;
    }

    function combineOpening(Opening memory opening, Commitment[] memory commitments)
        internal
        view
        returns (BN254.G1Point memory sumCm, uint256 sumValue, uint256 sumBlinding, bool ok)
    {
        sumCm = BN254.G1Point(0, 0);
        sumValue = 0;
        sumBlinding = 0;
        for (uint256 j = 0; j < opening.labels.length; j++) {
            (BN254.G1Point memory cm, bool found) = findCommitment(commitments, opening.labels[j]);
            if (!found) {
                return (sumCm, sumValue, sumBlinding, false);
            }
            uint256 factor = powMod(opening.gamma, j);
            sumCm = BN254.add(sumCm, BN254.mul(cm, factor));
            sumValue = addMod(sumValue, mulmod(opening.values[j] % FR_MOD, factor, FR_MOD));
            sumBlinding = addMod(sumBlinding, mulmod(opening.blindings[j] % FR_MOD, factor, FR_MOD));
        }
        ok = true;
    }

    function computeTranscript(Proof memory proof)
        internal
        pure
        returns (uint256 alpha, uint256 beta, uint256 zeta, uint256 rFs)
    {
        bytes memory transcript =
            bytes.concat(serializeFr(proof.publicInputs.n), serializeFr(proof.publicInputs.candidates));
        if (proof.kind == KIND_MAIN) {
            transcript = bytes.concat(
                transcript, serializeFr(proof.publicInputs.sumABallots), serializeFr(proof.publicInputs.sumM)
            );
            for (uint256 i = 0; i < proof.publicInputs.tally.length; i++) {
                transcript = bytes.concat(transcript, serializeFr(proof.publicInputs.tally[i]));
            }
            bytes memory qBytes;
            for (uint256 i = 0; i < proof.commitments.length; i++) {
                Commitment memory c = proof.commitments[i];
                bytes memory encoded = serializeG1(c.point);
                if (c.label == LABEL_Q) {
                    qBytes = encoded;
                } else {
                    transcript = bytes.concat(transcript, encoded);
                }
            }
            require(qBytes.length == 32, "missing Q commitment");
            alpha = hashToFr(bytes.concat(transcript, bytes("alpha")));
            transcript = bytes.concat(transcript, qBytes);
            zeta = hashToFr(bytes.concat(transcript, bytes("zeta")));
            beta = 0;
            rFs = 0;
        } else if (proof.kind == KIND_INCLUSION) {
           
            uint256 baseCount = 0;
            bytes memory derivedBytes = new bytes(0);
            bytes memory qBytesIncl;
            for (uint256 i = 0; i < proof.commitments.length; i++) {
                Commitment memory c = proof.commitments[i];
                bytes memory encoded = serializeG1(c.point);
                if (c.label == LABEL_Q_INCL) {
                    qBytesIncl = encoded;
                    continue;
                }
                if (baseCount < 6) {
                    transcript = bytes.concat(transcript, encoded);
                    baseCount++;
                } else {
                    derivedBytes = bytes.concat(derivedBytes, encoded);
                }
            }
            require(qBytesIncl.length == 32, "missing Q");
            alpha = hashToFr(bytes.concat(transcript, bytes("inclusion-alpha")));
            rFs = hashToFr(bytes.concat(transcript, bytes("inclusion-r")));
            transcript = bytes.concat(transcript, derivedBytes);
            beta = hashToFr(bytes.concat(transcript, bytes("inclusion-beta")));
            transcript = bytes.concat(transcript, qBytesIncl);
            zeta = hashToFr(bytes.concat(transcript, bytes("inclusion-zeta")));
        } else {
            transcript = bytes.concat(
                transcript, serializeFr(proof.publicInputs.disputedCode), serializeFr(proof.publicInputs.ballotIndex)
            );
            bytes memory qBytesRcpt;
            for (uint256 i = 0; i < proof.commitments.length; i++) {
                Commitment memory c = proof.commitments[i];
                bytes memory encoded = serializeG1(c.point);
                if (c.label == LABEL_Q_RECEIPT) {
                    qBytesRcpt = encoded;
                } else {
                    transcript = bytes.concat(transcript, encoded);
                }
            }
            require(qBytesRcpt.length == 32, "missing Q");
            alpha = hashToFr(bytes.concat(transcript, bytes("receipt-alpha")));
            transcript = bytes.concat(transcript, qBytesRcpt);
            zeta = hashToFr(bytes.concat(transcript, bytes("receipt-zeta")));
            beta = 0;
            rFs = 0;
        }
    }

    function constraintsAtZetaMain(
        uint256 alpha,
        uint256 zeta,
        uint256 omega,
        PublicInputs memory pub,
        Opening[] memory openings
    ) internal pure returns (bool, uint256, uint256) {
        EvalCache memory ev;
        bool ok;
        (ok, ev.a,) = getEval(openings, LABEL_A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.m,) = getEval(openings, LABEL_M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.sblkA,) = getEval(openings, LABEL_SBLK_A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.sblkM,) = getEval(openings, LABEL_SBLK_M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.accA,) = getEval(openings, LABEL_ACC_A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.accM,) = getEval(openings, LABEL_ACC_M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.tallyAcc,) = getEval(openings, LABEL_TALLY_ACC, zeta);
        if (!ok) return (false, 0, 0);

        uint256 blockASum = 0;
        uint256 blockMSum = 0;
        uint256 value;
        for (uint256 k = 0; k < pub.candidates; k++) {
            uint256 shift = mulmod(zeta, powMod(omega, k), FR_MOD);
            (ok, value,) = getEval(openings, LABEL_A, shift);
            if (!ok) return (false, 0, 0);
            blockASum = addMod(blockASum, value);
            (ok, value,) = getEval(openings, LABEL_M, shift);
            if (!ok) return (false, 0, 0);
            blockMSum = addMod(blockMSum, value);
        }

        uint256 zetaOmega = mulmod(zeta, omega, FR_MOD);
        (ok, ev.accAShift,) = getEval(openings, LABEL_ACC_A, zetaOmega);
        if (!ok) return (false, 0, 0);
        (ok, ev.accMShift,) = getEval(openings, LABEL_ACC_M, zetaOmega);
        if (!ok) return (false, 0, 0);

        uint256 omegaC = powMod(omega, pub.candidates);
        (ok, ev.tallyShift,) = getEval(openings, LABEL_TALLY_ACC, mulmod(zeta, omegaC, FR_MOD));
        if (!ok) return (false, 0, 0);

        (ok, ev.zPad,) = getEval(openings, LABEL_ZPAD, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.selBlkA,) = getEval(openings, LABEL_SEL_BLK_A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z1a,) = getEval(openings, LABEL_Z1A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z2a,) = getEval(openings, LABEL_Z2A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z3a,) = getEval(openings, LABEL_Z3A, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z1m,) = getEval(openings, LABEL_Z1M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z2m,) = getEval(openings, LABEL_Z2M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.z3m,) = getEval(openings, LABEL_Z3M, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.tailKeep,) = getEval(openings, LABEL_TAIL_KEEP, zeta);
        if (!ok) return (false, 0, 0);
        (ok, ev.tailSkip,) = getEval(openings, LABEL_TAIL_SKIP, zeta);
        if (!ok) return (false, 0, 0);

        uint256 sumATotal = mulmod(pub.sumABallots % FR_MOD, pub.candidates % FR_MOD, FR_MOD);
        uint256 sumMTotal = pub.sumM % FR_MOD;

        uint256[] memory constraints = new uint256[](17 + pub.candidates);
        uint256 idx = 0;

        constraints[idx++] = mulmod(ev.a, ev.zPad, FR_MOD);
        constraints[idx++] = mulmod(ev.a, subMod(ev.a, 1), FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.sblkA, blockASum), ev.selBlkA, FR_MOD);

        uint256 masked = mulmod(ev.sblkA, ev.selBlkA, FR_MOD);
        constraints[idx++] = mulmod(masked, subMod(masked, pub.candidates), FR_MOD);
        constraints[idx++] = mulmod(subMod(subMod(ev.accA, ev.a), ev.accAShift), ev.z1a, FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.accA, ev.a), ev.z2a, FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.accA, sumATotal), ev.z3a, FR_MOD);

        constraints[idx++] = mulmod(ev.m, ev.zPad, FR_MOD);
        constraints[idx++] = mulmod(ev.m, subMod(ev.m, 1), FR_MOD);
        constraints[idx++] = subMod(ev.sblkM, blockMSum);
        constraints[idx++] = mulmod(ev.sblkM, subMod(ev.sblkM, 1), FR_MOD);
        constraints[idx++] = mulmod(subMod(subMod(ev.accM, ev.m), ev.accMShift), ev.z1m, FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.accM, ev.m), ev.z2m, FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.accM, sumMTotal), ev.z3m, FR_MOD);
        constraints[idx++] = mulmod(ev.a, ev.m, FR_MOD);
        constraints[idx++] = mulmod(subMod(ev.tallyAcc, ev.m), ev.tailKeep, FR_MOD);
        constraints[idx++] = mulmod(subMod(subMod(ev.tallyAcc, ev.m), ev.tallyShift), ev.tailSkip, FR_MOD);

        for (uint256 c = 0; c < pub.candidates; c++) {
            (ok, value,) = getEval(openings, candidateLabel(c), zeta);
            if (!ok) return (false, 0, 0);
            constraints[idx++] = mulmod(subMod(ev.tallyAcc, pub.tally[c] % FR_MOD), value, FR_MOD);
        }

        uint256 pvanish = aggregateConstraints(alpha, constraints);
        (ok, value,) = getEval(openings, LABEL_Q, zeta);
        if (!ok) return (false, 0, 0);
        return (true, pvanish, value);
    }

    function findCommitment(Commitment[] memory commitments, uint16 label)
        internal
        pure
        returns (BN254.G1Point memory, bool)
    {
        for (uint256 i = 0; i < commitments.length; i++) {
            if (commitments[i].label == label) {
                return (commitments[i].point, true);
            }
        }
        return (BN254.G1Point(0, 0), false);
    }

    function getEval(Opening[] memory openings, uint16 label, uint256 point)
        internal
        pure
        returns (bool, uint256, uint256)
    {
        for (uint256 i = 0; i < openings.length; i++) {
            if (openings[i].point % FR_MOD != point % FR_MOD) {
                continue;
            }
            for (uint256 j = 0; j < openings[i].labels.length; j++) {
                if (openings[i].labels[j] == label) {
                    return (true, openings[i].values[j] % FR_MOD, openings[i].blindings[j] % FR_MOD);
                }
            }
        }
        return (false, 0, 0);
    }

    function aggregateConstraints(uint256 alpha, uint256[] memory constraints) internal pure returns (uint256) {
        uint256 acc = 0;
        uint256 alphaPow = 1;
        for (uint256 i = 0; i < constraints.length; i++) {
            acc = addMod(acc, mulmod(constraints[i], alphaPow, FR_MOD));
            alphaPow = mulmod(alphaPow, alpha, FR_MOD);
        }
        return acc;
    }

    function deriveR(Opening[] memory openings) internal pure returns (uint256) {
        bytes memory blob = new bytes(0);
        for (uint256 i = 0; i < openings.length; i++) {
            Opening memory o = openings[i];
            blob = bytes.concat(blob, serializeFr(o.point));
            blob = bytes.concat(blob, serializeFr(o.gamma));
            blob = bytes.concat(blob, serializeG1(o.witness));
            for (uint256 j = 0; j < o.values.length; j++) {
                blob = bytes.concat(blob, serializeFr(o.values[j]));
                blob = bytes.concat(blob, serializeFr(o.blindings[j]));
            }
        }
        return hashToFr(blob);
    }

    function rootOfUnity(uint256 n) internal pure returns (uint256) {
        require(n > 0 && (n & (n - 1)) == 0, "not power of 2");
        uint256 exp = (FR_MOD - 1) / n;
        return powMod(GENERATOR, exp);
    }

    function candidateLabel(uint256 idx) internal pure returns (uint16) {
        return LABEL_CAND_BASE + uint16(idx);
    }

    function constraintsAtZetaInclusion(
        uint256 alpha,
        uint256 beta,
        uint256 zeta,
        uint256 rFs,
        uint256 omega,
        PublicInputs memory pub,
        Opening[] memory openings
    ) internal pure returns (bool, uint256, uint256, uint256) {
        bool ok;
        uint256 bid;
        uint256 confirm;
        uint256 mVal;
        uint256 bidSh;
        uint256 confirmSh;
        uint256 mSh;
        uint256 t;
        uint256 tPrime;
        uint256 t1;
        uint256 t2;
        uint256 accT1;
        uint256 accT2;
        uint256 qEval;

        (ok, bid,) = getEval(openings, LABEL_BID, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, confirm,) = getEval(openings, LABEL_CCONFIRM, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, mVal,) = getEval(openings, LABEL_M_INCL, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, bidSh,) = getEval(openings, LABEL_BID_SH, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, confirmSh,) = getEval(openings, LABEL_CCONFIRM_SH, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, mSh,) = getEval(openings, LABEL_M_SH, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, t,) = getEval(openings, LABEL_T, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, tPrime,) = getEval(openings, LABEL_TPRIME, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, t1,) = getEval(openings, LABEL_T1, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, t2,) = getEval(openings, LABEL_T2, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, accT1,) = getEval(openings, LABEL_ACCT1, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, accT2,) = getEval(openings, LABEL_ACCT2, zeta);
        if (!ok) return (false, 0, 0, 0);
        (ok, qEval,) = getEval(openings, LABEL_Q_INCL, zeta);
        if (!ok) return (false, 0, 0, 0);

        uint256 accT1Shift;
        uint256 accT2Shift;
        uint256 zetaOmega = mulmod(zeta, omega, FR_MOD);
        (ok, accT1Shift,) = getEval(openings, LABEL_ACCT1, zetaOmega);
        if (!ok) return (false, 0, 0, 0);
        (ok, accT2Shift,) = getEval(openings, LABEL_ACCT2, zetaOmega);
        if (!ok) return (false, 0, 0, 0);

        uint256 zh = subMod(powMod(zeta, pub.n), 1);
        uint256 last = powMod(omega, pub.n - 1);

        uint256 z1 = mulmod(zh, inverse(subMod(zeta, last)), FR_MOD);
        uint256 z2 = subMod(zeta, last);
        uint256 z3 = mulmod(zh, inverse(subMod(zeta, 1)), FR_MOD);

        uint256 p1 = mulmod(subMod(accT1, t1), z1, FR_MOD);
        uint256 p2 = mulmod(subMod(accT2, t2), z1, FR_MOD);
        uint256 p3 = mulmod(subMod(accT1, mulmod(t1, accT1Shift, FR_MOD)), z2, FR_MOD);
        uint256 p4 = mulmod(subMod(accT2, mulmod(t2, accT2Shift, FR_MOD)), z2, FR_MOD);
        uint256 p5 = mulmod(subMod(accT1, accT2), z3, FR_MOD);
        uint256 p6 = subMod(t1, subMod(rFs, t));
        uint256 p7 = subMod(t2, subMod(rFs, tPrime));

        uint256[] memory constraints = new uint256[](7);
        constraints[0] = p1;
        constraints[1] = p2;
        constraints[2] = p3;
        constraints[3] = p4;
        constraints[4] = p5;
        constraints[5] = p6;
        constraints[6] = p7;

        uint256 acc = 0;
        uint256 betaPow = 1;
        for (uint256 i = 0; i < constraints.length; i++) {
            acc = addMod(acc, mulmod(constraints[i], betaPow, FR_MOD));
            betaPow = mulmod(betaPow, beta, FR_MOD);
        }
        return (true, acc, qEval, zh);
    }

    function constraintsAtZetaReceipt(
        uint256 alpha,
        uint256 zeta,
        uint256 omega,
        PublicInputs memory pub,
        Opening[] memory openings
    ) internal pure returns (bool, uint256, uint256, uint256, uint256) {
        bool ok;
        uint256 confirm;
        uint256 d;
        uint256 sel;
        uint256 accSel;
        uint256 accSelShift;
        uint256 qEval;
        (ok, confirm,) = getEval(openings, LABEL_CCONFIRM_RECEIPT, zeta);
        if (!ok) return (false, 0, 0, 0, 0);
        (ok, d,) = getEval(openings, LABEL_D, zeta);
        if (!ok) return (false, 0, 0, 0, 0);
        (ok, sel,) = getEval(openings, LABEL_SEL, zeta);
        if (!ok) return (false, 0, 0, 0, 0);
        (ok, accSel,) = getEval(openings, LABEL_ACC_SEL, zeta);
        if (!ok) return (false, 0, 0, 0, 0);
        uint256 zetaOmega = mulmod(zeta, omega, FR_MOD);
        (ok, accSelShift,) = getEval(openings, LABEL_ACC_SEL, zetaOmega);
        if (!ok) return (false, 0, 0, 0, 0);
        (ok, qEval,) = getEval(openings, LABEL_Q_RECEIPT, zeta);
        if (!ok) return (false, 0, 0, 0, 0);

        uint256 zh = subMod(powMod(zeta, pub.n), 1);
        uint256 last = powMod(omega, pub.n - 1);
        uint256 z1 = mulmod(zh, inverse(subMod(zeta, last)), FR_MOD);
        uint256 z2 = subMod(zeta, last);
        uint256 z3 = mulmod(zh, inverse(subMod(zeta, 1)), FR_MOD);

        uint256 selTimesD = mulmod(sel, d, FR_MOD);
        uint256 p1 = mulmod(subMod(accSel, selTimesD), z1, FR_MOD);
        uint256 p2 = mulmod(subMod(subMod(accSel, selTimesD), accSelShift), z2, FR_MOD);
        uint256 p3 = mulmod(accSel, z3, FR_MOD);

        uint256 p4 = mulmod(d, subMod(d, 1), FR_MOD);

        uint256[] memory constraints = new uint256[](4);
        constraints[0] = p1;
        constraints[1] = p2;
        constraints[2] = p3;
        constraints[3] = p4;

        uint256 acc = 0;
        uint256 alphaPow = 1;
        for (uint256 i = 0; i < constraints.length; i++) {
            acc = addMod(acc, mulmod(constraints[i], alphaPow, FR_MOD));
            alphaPow = mulmod(alphaPow, alpha, FR_MOD);
        }
        uint256 delta = subMod(confirm, pub.disputedCode % FR_MOD);
        uint256 fermat = powMod(delta, FR_MOD - 1);
        uint256 expectedD = subMod(1, fermat);
        uint256 receiptEq = subMod(d, expectedD);
        return (true, acc, qEval, zh, receiptEq);
    }

    function powMod(uint256 base, uint256 exp) internal pure returns (uint256 result) {
        base %= FR_MOD;
        result = 1;
        while (exp > 0) {
            if ((exp & 1) == 1) {
                result = mulmod(result, base, FR_MOD);
            }
            base = mulmod(base, base, FR_MOD);
            exp >>= 1;
        }
    }

    function inverse(uint256 a) internal pure returns (uint256) {
        return powMod(a, FR_MOD - 2);
    }

    function addMod(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, FR_MOD);
    }

    function subMod(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a >= b) {
            return a - b;
        }
        return FR_MOD - ((b - a) % FR_MOD);
    }

    function serializeFr(uint256 fr) internal pure returns (bytes memory out) {
        out = new bytes(32);
        uint256 v = fr % FR_MOD;
        for (uint256 i = 0; i < 32; i++) {
            out[i] = bytes1(uint8(v & 0xff));
            v >>= 8;
        }
    }

    function serializeFq(uint256 fq) internal pure returns (bytes memory out) {
        out = new bytes(32);
        uint256 v = fq % FQ_MOD;
        for (uint256 i = 0; i < 32; i++) {
            out[i] = bytes1(uint8(v & 0xff));
            v >>= 8;
        }
    }

    function serializeG1(BN254.G1Point memory p) internal pure returns (bytes memory) {
        bytes memory out = serializeFq(p.x);
        if (p.x == 0 && p.y == 0) {
            out[31] = bytes1(uint8(out[31]) | 0x40);
            return out;
        }
        uint256 y = p.y % FQ_MOD;
        uint256 negY = y == 0 ? 0 : FQ_MOD - y;
        bool yIsPositive = y <= negY;
        if (!yIsPositive) {
            out[31] = bytes1(uint8(out[31]) | 0x80);
        }
        return out;
    }

    function hashToFr(bytes memory data) internal pure returns (uint256) {
        bytes32 digest = sha256(data);
        uint256 acc = 0;
        for (uint256 i = 0; i < 32; i++) {
            acc |= (uint256(uint8(digest[i])) << (8 * i));
        }
        return acc % FR_MOD;
    }
}
