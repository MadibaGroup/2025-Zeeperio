// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../src/ZeeperioBN254Verifier.sol";

contract ZeeperioVerifierHarness is ZeeperioBN254Verifier {
    function exposeComputeTranscript(Proof memory proof)
        external
        pure
        returns (uint256 alpha, uint256 beta, uint256 zeta, uint256 rFs)
    {
        return computeTranscript(proof);
    }

    function exposeDeriveR(Opening[] memory openings) external pure returns (uint256) {
        return deriveR(openings);
    }

    function exposePairing(Proof memory proof) external view returns (bool) {
        return pairingCheck(proof);
    }

    function exposePairingOpening(Opening memory opening, Commitment[] memory commitments)
        external
        view
        returns (bool)
    {
        (BN254.G1Point memory sumCm, uint256 sumValue, uint256 sumBlinding, bool ok) =
            combineOpening(opening, commitments);
        if (!ok) return false;
        BN254.G1Point memory sumCommittedEval = BN254.add(BN254.mul(vk_g, sumValue), BN254.mul(vk_gamma_g, sumBlinding));
        BN254.G1Point memory left = BN254.add(sumCm, BN254.negate(sumCommittedEval));
        left = BN254.add(left, BN254.mul(opening.witness, opening.point % FR_MOD));
        return BN254.pairingProd2(left, vk_h, BN254.negate(opening.witness), vk_beta_h);
    }

    function exposeLeft(Opening memory opening, Commitment[] memory commitments)
        external
        view
        returns (BN254.G1Point memory)
    {
        (BN254.G1Point memory sumCm, uint256 sumValue, uint256 sumBlinding, bool ok) =
            combineOpening(opening, commitments);
        require(ok, "combine failed");
        BN254.G1Point memory sumCommittedEval = BN254.add(BN254.mul(vk_g, sumValue), BN254.mul(vk_gamma_g, sumBlinding));
        BN254.G1Point memory left = BN254.add(sumCm, BN254.negate(sumCommittedEval));
        left = BN254.add(left, BN254.mul(opening.witness, opening.point % FR_MOD));
        return left;
    }

    function exposeCombine(Opening memory opening, Commitment[] memory commitments)
        external
        view
        returns (BN254.G1Point memory, uint256, uint256, bool)
    {
        return combineOpening(opening, commitments);
    }

    function exposeComponents(Opening memory opening, Commitment[] memory commitments)
        external
        view
        returns (BN254.G1Point memory sumCm, BN254.G1Point memory sumCommittedEval, BN254.G1Point memory witnessMul)
    {
        uint256 sumValue;
        uint256 sumBlinding;
        (sumCm, sumValue, sumBlinding,) = combineOpening(opening, commitments);
        sumCommittedEval = BN254.add(BN254.mul(vk_g, sumValue), BN254.mul(vk_gamma_g, sumBlinding));
        witnessMul = BN254.mul(opening.witness, opening.point % FR_MOD);
    }

    function exposeConstraintsMain(
        uint256 alpha,
        uint256 zeta,
        uint256 omega,
        PublicInputs memory pub,
        Opening[] memory openings
    ) external pure returns (bool, uint256, uint256) {
        return constraintsAtZetaMain(alpha, zeta, omega, pub, openings);
    }

    function exposeRoot(uint256 n) external pure returns (uint256) {
        return rootOfUnity(n);
    }

    function exposeFrMod() external pure returns (uint256) {
        return FR_MOD;
    }
}

contract ZeeperioBN254VerifierTest is Test {
    using stdJson for string;

    ZeeperioBN254Verifier verifier;
    ZeeperioVerifierHarness harness;
    uint8 constant KIND_MAIN = 0;
    uint8 constant KIND_INCLUSION = 1;
    uint8 constant KIND_RECEIPT = 2;

    function setUp() public {
        harness = new ZeeperioVerifierHarness();
        verifier = ZeeperioBN254Verifier(address(harness));
    }

    function _loadCalldata(string memory path) internal view returns (bytes memory) {
        string memory json = vm.readFile(path);
        string memory calldataHex = stdJson.readString(json, ".calldata");
        return vm.parseBytes(calldataHex);
    }

    function _fixturePath(string memory filename) internal view returns (string memory path) {
        path = string.concat(vm.projectRoot(), "/fixtures/", filename);
        require(vm.exists(path), "missing fixture");
    }

    function _decode(bytes memory proofCalldata) internal pure returns (ZeeperioBN254Verifier.Proof memory proof) {
        proof = abi.decode(proofCalldata, (ZeeperioBN254Verifier.Proof));
    }

    function test_verify_main_fixture() public {
        string memory path = _fixturePath("calldata_main.json");
        ZeeperioBN254Verifier.Proof memory jsonProof = _loadProof(vm.readFile(path));
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        assertEq(proof.kind, KIND_MAIN, "kind mismatch");
        bytes32 jsonHash = keccak256(abi.encode(jsonProof));
        bytes32 decodedHash = keccak256(abi.encode(proof));
        bytes32 rawHash = keccak256(proofCalldata);
        emit log_bytes32(jsonHash);
        emit log_bytes32(decodedHash);
        emit log_bytes32(rawHash);
        assertEq(proof.publicInputs.n, jsonProof.publicInputs.n, "n mismatch");
        assertEq(proof.publicInputs.candidates, jsonProof.publicInputs.candidates, "candidates mismatch");
        assertEq(proof.publicInputs.tally.length, jsonProof.publicInputs.tally.length, "tally len mismatch");
        assertEq(proof.commitments.length, jsonProof.commitments.length, "commitment len mismatch");
        assertEq(proof.openings.length, jsonProof.openings.length, "openings len mismatch");
        assertEq(proof.alpha, jsonProof.alpha, "alpha payload mismatch");
        assertEq(proof.zeta, jsonProof.zeta, "zeta payload mismatch");
        assertEq(jsonHash, decodedHash, "json vs decoded proof mismatch");
        assertEq(decodedHash, rawHash, "calldata bytes mismatch");
        emit log_named_uint("sumA", proof.publicInputs.sumABallots);
        emit log_named_uint("sumM", proof.publicInputs.sumM);
        emit log_named_uint("tally0", proof.publicInputs.tally[0]);
        emit log_named_uint("tally1", proof.publicInputs.tally[1]);
        emit log_named_uint("tally2", proof.publicInputs.tally[2]);
        emit log_named_uint("opening0_gamma", proof.openings[0].gamma);
        emit log_named_uint("opening0_point", proof.openings[0].point);
        emit log_named_uint("opening0_value0", proof.openings[0].values[0]);
        emit log_named_uint("opening0_blinding0", proof.openings[0].blindings[0]);
        emit log_named_uint("opening0_labels_len", proof.openings[0].labels.length);
        emit log_named_uint("opening0_label0", proof.openings[0].labels[0]);
        (uint256 alpha,, uint256 zeta,) = harness.exposeComputeTranscript(proof);
        uint256 frMod = harness.exposeFrMod();
        emit log_named_uint("alpha stored", proof.alpha);
        emit log_named_uint("alpha computed", alpha);
        assertEq(alpha % frMod, proof.alpha % frMod, "alpha mismatch");
        assertEq(zeta % frMod, proof.zeta % frMod, "zeta mismatch");
        uint256 rDerived = harness.exposeDeriveR(proof.openings);
        assertEq(rDerived % frMod, proof.r % frMod, "r mismatch");
        BN254.G1Point memory left0 = harness.exposeLeft(proof.openings[0], proof.commitments);
        emit log_named_uint("left0_x", left0.x);
        emit log_named_uint("left0_y", left0.y);
        (BN254.G1Point memory sumCm0, uint256 sumValue0, uint256 sumBlinding0,) =
            harness.exposeCombine(proof.openings[0], proof.commitments);
        emit log_named_uint("sumCm0_x", sumCm0.x);
        emit log_named_uint("sumCm0_y", sumCm0.y);
        emit log_named_uint("sumValue0", sumValue0);
        emit log_named_uint("sumBlinding0", sumBlinding0);
        (BN254.G1Point memory sumCmC, BN254.G1Point memory sumCommittedEval, BN254.G1Point memory witnessMul) =
            harness.exposeComponents(proof.openings[0], proof.commitments);
        emit log_named_uint("sumCmC_x", sumCmC.x);
        emit log_named_uint("sumCmC_y", sumCmC.y);
        emit log_named_uint("sumCommEval_x", sumCommittedEval.x);
        emit log_named_uint("sumCommEval_y", sumCommittedEval.y);
        emit log_named_uint("witnessMul_x", witnessMul.x);
        emit log_named_uint("witnessMul_y", witnessMul.y);
        for (uint256 i = 0; i < proof.openings.length; i++) {
            assertTrue(
                harness.exposePairingOpening(proof.openings[i], proof.commitments),
                string.concat("pairing opening ", vm.toString(i))
            );
        }
        assertTrue(harness.exposePairing(proof), "pairing check");
        uint256 omega = harness.exposeRoot(proof.publicInputs.n);
        (bool ok,,) = harness.exposeConstraintsMain(alpha, zeta, omega, proof.publicInputs, proof.openings);
        assertTrue(ok, "constraint check");
        assertTrue(verifier.verify(jsonProof), "json proof should verify");
        assertTrue(verifier.verifyMain(proofCalldata), "main fixture should verify");
    }

    function test_verify_inclusion_fixture() public {
        string memory path = _fixturePath("calldata_inclusion.json");
        ZeeperioBN254Verifier.Proof memory jsonProof = _loadProof(vm.readFile(path));
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        assertEq(proof.kind, KIND_INCLUSION, "kind mismatch");
        assertEq(keccak256(abi.encode(jsonProof)), keccak256(proofCalldata), "calldata bytes mismatch");
        assertTrue(verifier.verifyInclusion(proofCalldata), "inclusion fixture should verify");
    }

    function test_verify_receipt_fixture() public {
        string memory path = _fixturePath("calldata_receipt.json");
        ZeeperioBN254Verifier.Proof memory jsonProof = _loadProof(vm.readFile(path));
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        assertEq(proof.kind, KIND_RECEIPT, "kind mismatch");
        assertEq(keccak256(abi.encode(jsonProof)), keccak256(proofCalldata), "calldata bytes mismatch");
        assertTrue(verifier.verifyReceipt(proofCalldata), "receipt fixture should verify");
    }

    function test_verify_emits_event() public {
        bytes memory proofCalldata = _loadCalldata(_fixturePath("calldata_main.json"));
        vm.expectEmit(true, true, true, true, address(verifier));
        emit ZeeperioBN254Verifier.Verified(KIND_MAIN, keccak256(proofCalldata), address(this));
        verifier.verifyMain(proofCalldata);
    }

    function _loadProof(string memory json) internal view returns (ZeeperioBN254Verifier.Proof memory proof) {
        ZeeperioBN254Verifier.PublicInputs memory pub;
        uint256 kindVal = stdJson.readUint(json, ".kind");
        pub.n = stdJson.readUint(json, ".public_inputs.n");
        pub.candidates = stdJson.readUint(json, ".public_inputs.candidates");
        pub.sumABallots = stdJson.readUint(json, ".public_inputs.sum_a_ballots");
        pub.sumM = stdJson.readUint(json, ".public_inputs.sum_m");
        pub.tally = stdJson.readUintArray(json, ".public_inputs.tally");
        if (kindVal == KIND_RECEIPT) {
            pub.disputedCode = stdJson.readUint(json, ".public_inputs.disputed_code");
            pub.ballotIndex = stdJson.readUint(json, ".public_inputs.ballot_index");
        }

        uint256 commitmentCount = _countByUint(json, ".commitments", ".label");
        ZeeperioBN254Verifier.Commitment[] memory commitments = new ZeeperioBN254Verifier.Commitment[](commitmentCount);
        for (uint256 i = 0; i < commitmentCount; i++) {
            string memory prefix = string.concat(".commitments[", vm.toString(i), "]");
            commitments[i] = ZeeperioBN254Verifier.Commitment({
                label: uint16(stdJson.readUint(json, string.concat(prefix, ".label"))),
                point: BN254.G1Point({
                    x: parseHex(stdJson.readString(json, string.concat(prefix, ".x"))),
                    y: parseHex(stdJson.readString(json, string.concat(prefix, ".y")))
                })
            });
        }

        uint256 openingsCount = _countByString(json, ".openings", ".point");
        ZeeperioBN254Verifier.Opening[] memory openings = new ZeeperioBN254Verifier.Opening[](openingsCount);
        for (uint256 i = 0; i < openingsCount; i++) {
            string memory prefix = string.concat(".openings[", vm.toString(i), "]");
            openings[i] = ZeeperioBN254Verifier.Opening({
                witness: BN254.G1Point({
                    x: parseHex(stdJson.readString(json, string.concat(prefix, ".witness[0]"))),
                    y: parseHex(stdJson.readString(json, string.concat(prefix, ".witness[1]")))
                }),
                point: parseFrLe(stdJson.readString(json, string.concat(prefix, ".point"))),
                gamma: parseFrLe(stdJson.readString(json, string.concat(prefix, ".gamma"))),
                labels: toUint16Array(stdJson.readUintArray(json, string.concat(prefix, ".labels"))),
                values: toFrArray(stdJson.readStringArray(json, string.concat(prefix, ".values"))),
                blindings: toFrArray(stdJson.readStringArray(json, string.concat(prefix, ".blindings")))
            });
        }

        proof = ZeeperioBN254Verifier.Proof({
            kind: uint8(kindVal),
            commitments: commitments,
            openings: openings,
            publicInputs: pub,
            alpha: parseFrLe(stdJson.readString(json, ".alpha")),
            beta: parseFrLe(stdJson.readString(json, ".beta")),
            zeta: parseFrLe(stdJson.readString(json, ".zeta")),
            r: parseFrLe(stdJson.readString(json, ".r"))
        });
    }

    function parseFrLe(string memory input) internal pure returns (uint256 out) {
        bytes memory strBytes = bytes(input);
        uint256 start = 0;
        if (
            strBytes.length >= 2 && strBytes[0] == bytes1("0")
                && (strBytes[1] == bytes1("x") || strBytes[1] == bytes1("X"))
        ) {
            start = 2;
        }
        for (uint256 i = start; i + 1 < strBytes.length; i += 2) {
            uint8 high = _fromHexChar(strBytes[i]);
            uint8 low = _fromHexChar(strBytes[i + 1]);
            uint8 b = (high << 4) | low;
            out |= uint256(b) << (8 * ((i - start) / 2));
        }
    }

    function parseHex(string memory input) internal pure returns (uint256 out) {
        bytes memory strBytes = bytes(input);
        uint256 start = 0;
        if (
            strBytes.length >= 2 && strBytes[0] == bytes1("0")
                && (strBytes[1] == bytes1("x") || strBytes[1] == bytes1("X"))
        ) {
            start = 2;
        }
        for (uint256 i = start; i < strBytes.length; i++) {
            uint8 c = uint8(strBytes[i]);
            uint8 nibble;
            if (c >= 48 && c <= 57) {
                nibble = c - 48;
            } else if (c >= 97 && c <= 102) {
                nibble = c - 87;
            } else if (c >= 65 && c <= 70) {
                nibble = c - 55;
            } else {
                revert("invalid hex");
            }
            out = (out << 4) | nibble;
        }
    }

    function _fromHexChar(bytes1 c) private pure returns (uint8) {
        uint8 b = uint8(c);
        if (b >= 48 && b <= 57) {
            return b - 48;
        }
        if (b >= 97 && b <= 102) {
            return b - 87;
        }
        if (b >= 65 && b <= 70) {
            return b - 55;
        }
        revert("invalid hex");
    }

    function toFrArray(string[] memory inputs) internal pure returns (uint256[] memory out) {
        out = new uint256[](inputs.length);
        for (uint256 i = 0; i < inputs.length; i++) {
            out[i] = parseFrLe(inputs[i]);
        }
    }

    function toUint16Array(uint256[] memory inputs) internal pure returns (uint16[] memory out) {
        out = new uint16[](inputs.length);
        for (uint256 i = 0; i < inputs.length; i++) {
            out[i] = uint16(inputs[i]);
        }
    }

    function _countByUint(string memory json, string memory base, string memory leaf)
        internal
        view
        returns (uint256 count)
    {
        while (true) {
            string memory path = string.concat(base, "[", vm.toString(count), "]", leaf);
            try vm.parseJsonUint(json, path) {
                count++;
            } catch {
                break;
            }
        }
    }

    function _countByString(string memory json, string memory base, string memory leaf)
        internal
        view
        returns (uint256 count)
    {
        while (true) {
            string memory path = string.concat(base, "[", vm.toString(count), "]", leaf);
            try vm.parseJsonString(json, path) {
                count++;
            } catch {
                break;
            }
        }
    }
}
