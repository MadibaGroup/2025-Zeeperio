// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library BN254 {
    uint256 internal constant PRIME_Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.x, PRIME_Q - (p.y % PRIME_Q));
    }

    function add(G1Point memory p, G1Point memory q) internal view returns (G1Point memory r) {
        if (p.x == 0 && p.y == 0) {
            return q;
        }
        if (q.x == 0 && q.y == 0) {
            return p;
        }
        uint256[4] memory input = [p.x, p.y, q.x, q.y];
        bool success;
        assembly {
            //0x06 bn254 addition precompile
            success := staticcall(gas(), 6, input, 0x80, r, 0x40)
        }
        require(success, "fail");
    }

    function mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        if (p.x == 0 && p.y == 0 || s == 0) {
            return G1Point(0, 0);
        }
        uint256[3] memory input = [p.x, p.y, s];
        bool success;
        assembly {
            //0x07 bn254 scalar mul precompile
            success := staticcall(gas(), 7, input, 0x60, r, 0x40)
        }
        require(success, "fail");
    }

    function pairingProd2(G1Point memory p1, G2Point memory q1, G1Point memory p2, G2Point memory q2)
        internal
        view
        returns (bool)
    {
        uint256[12] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = q1.x[1];
        input[3] = q1.x[0];
        input[4] = q1.y[1];
        input[5] = q1.y[0];
        input[6] = p2.x;
        input[7] = p2.y;
        input[8] = q2.x[1];
        input[9] = q2.x[0];
        input[10] = q2.y[1];
        input[11] = q2.y[0];

        uint256[1] memory out;
        bool success;
        assembly {
            //0x08 bn254 pairing precompile
            success := staticcall(gas(), 8, input, 0x180, out, 0x20)
        }
        return success && out[0] == 1;
    }
}
