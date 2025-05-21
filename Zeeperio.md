# Zeeperio: Realcryptik for E2E Paper Ballot Voting

> [!WARNING]
>
> This section is just some ChatGPT generated filler.

After decades of efforts toward the adoption of end-to-end verifiable voting systems, we propose a compromise solution we term *realcryptik*—an homage to *realpolitik*, which prioritizes practical realities over idealized principles. While traditional cryptographic voting systems emphasize strict privacy guarantees and distrust of all parties, they often fail to gain traction due to a combination of deployment complexity, limited usability for voters and poll workers, lack of demand from election officials focused more on operational reliability than cryptographic assurances, and unclear cost-benefit incentives in political and institutional contexts that rarely reward technical rigour.

Realcryptik embraces a more pragmatic threat model: assuming that vendors or authorities may learn how individuals voted—but focusing instead on public verifiability, transparency, and resistance to large-scale manipulation. By aligning design goals with what election officials and voters demonstrably care about, we aim to offer a stepping stone between current unverifiable practices and the long-term vision of fully private, end-to-end verifiable elections.

While realcryptik does not eliminate challenges like deployment complexity or institutional inertia, it sidesteps the most brittle idealizations (like perfect privacy from all parties) and instead offers a pragmatic path toward verifiable elections that stakeholders are willing to adopt.



## Threat Model

> [!WARNING]
>
> This section is just some ChatGPT generated filler.

End-to-end verifiable (E2E-V) voting systems promise the strongest cryptographic guarantees: each voter can verify that their vote was correctly recorded and counted, and the public can verify the overall tally without trusting any single entity. These systems preserve ballot secrecy while providing mathematical assurance of integrity. However, in practice, E2E systems face considerable obstacles to adoption — including technical complexity, poor usability, burdensome operational procedures, and a lack of institutional demand. Election officials often prioritize simplicity, logistical feasibility, and voter confidence rooted in physical processes over cryptographic proofs that are difficult to explain or audit in the field.

On the opposite end of the spectrum lies a radically transparent model: publishing every individual’s vote publicly, effectively eliminating secrecy in favor of perfect verifiability. Such a system is trivial to audit and requires no cryptography at all, but it sacrifices the secret ballot — a core democratic value. While some niche settings (e.g., student elections or shareholder votes) tolerate this tradeoff, public vote disclosure invites coercion, vote-buying, and loss of voter autonomy at scale, especially in contentious or authoritarian contexts.

*Realcryptik* offers a middle path. It discards the ideal of perfect privacy from vendors or election officials — acknowledging that in many jurisdictions, such privacy is already compromised or unenforced — but retains the principle of verifiability. In a realcryptik system, the vote may be visible to infrastructure providers or insiders, but the *aggregate tally and audit trail* are publicly verifiable. Voters may not get end-to-end receipt-freeness, but they gain protection against silent tally manipulation or large-scale fraud. The emphasis shifts from cryptographic purity to operational realism: systems that are simpler to deploy, easier to explain, and more likely to be adopted without compromising all integrity guarantees.

While this approach is unlikely to satisfy the strongest privacy advocates, realcryptik aims to bridge the gap between the status quo of unverifiable black-box systems and the unrealized promise of full E2E-V systems. It reflects the political insight that *some verifiability now* may do more good than *perfect verifiability never*.

## Zeeperio Design 

| Example     | Main Primitives for E2E Integrity  | Main Primitives for Ballot Privacy    | Privacy Threat Model                                 |
| ----------- | ---------------------------------- | ------------------------------------- | ---------------------------------------------------- |
| Public vote | Inspection                         | None                                  | Anyone can learn how anyone voted                    |
| Helios      | Homomorphic encryption             | $\Sigma$-Protocols                    | No one can learn how anyone voted                    |
| Scantegrity | Commitments & cut-and-choose (C&C) | TEEs & commitments                    | No one can learn how anyone voted                    |
| FOO         | Inspection                         | Anonymous channels & blind signatures | No one can learn how anyone voted                    |
| Boardroom   | Verifiable secret sharing (VSS)    | VSS & multiparty computation (MPC)    | No one can learn how anyone voted                    |
| Zeeperio    | SNARKs                             | zk-SNARKs                             | Only the EA can learn how anyone voted (Realcryptik) |

## Protocol Overview

Zeeperio is a succinct argument that an election tally is correctly formed, which is independent of the number of voters ($\mathcal{V}$) and number of candidates ($\mathcal{C}$). Eperio is flexible backend for different paper-based ballots types, including Scantegity (but not Scantegrity II) and Pret a Voter. 

The simplicity of Eperio is based in part on a commit/reveal of all confirmation codes in the election. In Scantegrity II, voters only learn the confirmation code of the candidate they voted for. This allows for dispute resolution---a voter can argue the system incorrectly recorded their vote by revealing a different confirmation code. However Eperio cannot support Scantegrity II without a commit/reveal of individual codes, which evades the performance benefits of committing to all codes at once. In Zeeperio, we commit to all codes in a single polynomial commitment but can still selectively reveal individual codes or prove properties about them (such as a specific confirmation code does not appear anywhere on a specified ballot). 

The choice between Scantegrity, Scantegrity II, and Pret a Voter ballot styles depends on priorities. Scantegrity II is strictly "better" than Scantegrity in terms of security features, by offering dispute resolution without giving up anything. Pret a Voter does not offer dispute resolution but it does protect voter privacy from the optical scanner, whereas in Scantegrity II the scanner learns the tally. However because the paper ballot does not hide the vote, Scantegrity II allows manual recounts (which can be performed with risk limit auditing as all ballots have a serial number) in addition to the E2E proofs. Considering these completing features, we opt to design Zeeperio for Scantegrity II ballots---future work can examine how to adapt Zeeperio to Pret a Voter (it appears to require only minor modifications).

In addition to succinctness, we also clean up a few issues that were not fully resolved in Scantegrity II and Eperio:

* As pointed about by Basin et al, Eperio does not prove ballots were not overvoted, which Zeeperio can prove.
* As acknowledged by Essex et al, Eperio does not support Scantegrity II ballots but Zeeperio can
* As acknowledged by Chaum et al, Scantegrity II supports dispute resolution but it requires all confirmation codes on the ballot to be revealed. Zeeprio can offer a simple proof of incorrect code without revealing information about all codes. This is a slight tightening of security.

A remaining issue, pointed out by Basin et al, are clash attacks which are not explicitly addressed by Eperio. However they are applicable to all E2E voting systems and are addressed through strict polling place policies that denote which ballot is given to which voter. In Scantegrity II, a manual recount would also discover this attack. 

### Basic Poly-IOP model

Zeeperio is a polynomial interactive oracle proof (Poly-IOP). This model has been widely used in the literature so we do not review it.[^2] Roughly it provides a set of succinct arguments that can be made about vectors (or arrays or columns) of data, where each vector index holds an integer from $\mathbb{F}_q$ --- the exponent field of a pairing-friendly elliptic curve such as alt_bn128 or BLS12-38. For efficiency reasons, the vector is encoded into a polynomial at a set of indicies (called the domain) that form a multiplicative subgroup of $q$. The polynomials are committed to using a polynomial commitment scheme such as KZG commitments. The verifier receives commitments from the prover and never examines the full polynomials or the full vectors. The prover provides new commitments to polynomials that constrain the original polynomial, thereby proving certain properties about the polynomial. The verifier checks the polynomials are correctly formed by opening them at random points.

Poly-IOP arguments come in two flavours. The first (SNARKs) does not disclose the underlying data because the verifier does not have time to look at it, but does not explicitly try to hide it. The second (zk-SNARKs) ensures the underlying data is hidden. Adding zero knowledge to a Poly-IOP argument consists of two minor modifications. The first is that the hiding version of KZG (with randomizers akin to a Pedersen commitment) is used instead of the simpler deterministic version. The second, we term the MBKM heuristic[^1], randomizes each polynomial (with a $k$-th degree multiple of $Z_H$) before it is committed to. This ensures that an adversary with a guess of what the polynomial is cannot confirm the guess when the polynomial is opened up to $k$ times at different random points throughout the argument. In the future, will we simply say a "hiding commitment" as shorthand for randomized KZG plus the MBKM heuristic. 

Finally we will describe Zeeperio as an interactive protocol however it can be made non-interactive with the Fiat-Shamir heuristic. Extreme caution needs to be employed with Fiat-Shamir given improper usage is a common attack vector on zk-SNARK systems.  

[^1]: This technique—employed and popularized in Sonic by Maller, Bowe, Kohlweiss & Meiklejohn (2019)—lacks a standard name, variously referred to in the literature by variants on blinders, vanishing-polynomial blinding, the $Z_H$-mask trick, and off-domain masking. We propose calling it the MBKM heuristic.
[^2]: We refer the interested reader to zk-learning.org or plonkbook.org

### Spoiled Ballots

Before given an example, we quickly discuss spoiled ballots. There is no canonical way of dealing of spoiled ballots in the literature. Scantegrity II suggests adding a "spoil" option as a candidate to the ballot which gives voters who spoil their ballots a way to check correct inclusion, as opposed to simply undervoting the ballot which means voters to not receive any confirmation code.

We believe Zeerpio can be adapted to many different ways of handling spoiled ballots but the design changes substantially based on how they are handled. Thus, we make some upfront assumptions about it (future work can explore adapting Zeeperio to different assumptions). We adopt the "spoil candidate" approach of Scantegrity II. We assume the scanner will reject an undervoted ballot, and force the voter to select the "spoil candidate" option (or any other option) before accepting the ballot.

Given a spoil candidate, there is also no reason to accept an overvoted ballot. However an overvoted ballot cannot be fixed by the voter, as it is already exposed more than one confirmation code. We can either accept it and discard it from the tally, or we can reject it and force the voter to try again with a new ballot (selecting the spoil candidate as desired). Further, instead of disregarding the overvoted ballot, it can be converted to a print audit. So we assume the scanner rejects undervoted and overvoted ballots (however the EA may still maliciously insert these into the tally so we will deal with them in Zeeperio).

### Worked Example

Turning now to an example, consider an election with 5 ballots and 3 ballot options (2 candidates plus a spoil option): Yes, No and Spoil. 

| Ballot ID (Reference) | Ballot Position (Reference) | Code (Private/Pre) | Audit (Private/Post) | Mark (Private/Post) | Candidate (Reference) |
| --------------------- | --------------------------- | ------------------ | -------------------- | ------------------- | --------------------- |
| 000                   | 00                          | IWEND              | 0                    | 0                   | Yes                   |
| 000                   | 01                          | XJSED              | 0                    | 0                   | No                    |
| 000                   | 02                          | ENIPW              | 0                    | 1                   | Spoiled               |
| 001                   | 00                          | QEMCD              | 0                    | 1                   | Yes                   |
| 001                   | 01                          | DCEPY              | 0                    | 0                   | No                    |
| 001                   | 02                          | COWNT              | 0                    | 0                   | Spoiled               |
| 002                   | 00                          | MWINA              | 1                    | 0                   | Yes                   |
| 002                   | 01                          | CMIPW              | 1                    | 0                   | No                    |
| 002                   | 02                          | WNJOG              | 1                    | 0                   | Spoiled               |
| 003                   | 00                          | NCIES              | 0                    | 0                   | Yes                   |
| 003                   | 01                          | OWIES              | 0                    | 1                   | No                    |
| 003                   | 02                          | WWESN              | 0                    | 0                   | Spoiled               |
| 004                   | 00                          | CNEOW              | 0                    | 1                   | Yes                   |
| 004                   | 01                          | OODNV              | 0                    | 0                   | No                    |
| 004                   | 02                          | NEOPCS             | 0                    | 0                   | Spoiled               |
| Unused                |                             | 0                  | 0                    | 0                   |                       |

Before the election, the EA publishes the election parameters: $\mathcal{B}$ printed ballots and $\mathcal{C}$ candidates on each ballot. It creates all the columns above, except the Audit and Mark columns which are populated by the actual ballots cast in the election. Ballot ID, Ballot Position and Candidate columns are not actually needed in Zeeperio, we include them just to help visualize the protocol. Because these columns are ordered, the index of the column fully defines the contents of these three columns. For example, row 5 (counting from 0) must be ballot 002 ($\lfloor{5/2}\rfloor=2)$, ballot position 03 ($5 \bmod 2=3$), and spoiled (3rd candidate in the candidate list). The Code column is committed to. Its commitment is timestamped and published before any ballots are cast. 

After the election closes, the scanner tallies are provided to the EA which commits and publishes the Audit and Mark column. The EA also creates a data structure for the final tally as follows:

| **Candidate ID (Public)** | **Tally (Public)** |
| ------------------------- | ------------------ |
| Yes                       | 2                  |
| No                        | 1                  |
| Spoiled                   | 1                  |

#### Constraints

> [!Caution]
>
> May be incomplete, work in progress

Zeeperio is an argument that all the columns of both tables are correctly formed. It consists of proving the following facts (or constraints) about the columns.

1. Audit column
   1. 0 padded
   2. Binary
   3. All 0 or all 1 per ballot block
   4. Sum
2. Mark column
   1. 0 padded
   2. Binary
   3. 0 or 1 mark per ballot block
   4. Sum
3. Between Audit and Mark column
4. Tally is correctly computed from Mark
5. Voter checks
   1. Receipt check
   2. Print audit check
   3. Dispute resolution check

#### Notation

An election is setup with $\mathcal{B}$ printed ballots and $\mathcal{C}$ candidates on each ballot. This results in $\mathcal{P}=\mathcal{B}\cdot\mathcal{C}$ unique ballot positions and thus $\mathcal{P}$ confirmation codes. 

Those familiar with the Poly-IOP model will know that prover efficiency is improved by encoding column elements at polynomial indices that iterate over a multiplicative subgroup (this enables interpolation via FFT) and that elliptic curve parameters are often chosen to ensure many options for such subgroups are available. The most common approach in curve design is ensuring subgroups of sizes ${2,2^2,2^3,\ldots,2^n}$ for a reasonably large $n$ ($n=28$ for alt_bls and $n=32$ for BLS12-384). The bottom line is to commit to a column of, say, size 1000, you need to actually commit to a column of size 1024 (the size rounded up to the nearest power of 2). 

The final size of the column ($n=2^{\lfloor\log_2{\mathcal{P}}\rfloor}$) will be $\mathcal{P}$ rounded up to the nearest power of two. Columns will have content in the first $\mathcal{P}$ indices and then 0's as padding in any remaining indices. 

| Symbol        | Meaning                                                      |
| ------------- | ------------------------------------------------------------ |
| n             | size of column (with padding)                                |
| $\mathcal{B}$ | number of ballots                                            |
| $\mathcal{C}$ | number of candidates                                         |
| $\mathcal{P}$ | number of unique ballot positions ($\mathcal{B}\times\mathcal{C}$) |
| i             | counter over column (0 to $n$)                               |
| j             | counter over ballots (0 to $\mathcal{B}$)                    |
| k             | counter over positions within a ballot (0 to $\mathcal{C}$)  |
|               |                                                              |
|               |                                                              |

## Constraint 1: Audit Column

The audit column marks which ballots were selected for a print audit. This is denoted by the flag value $1$ in the column. Since ballots span $\mathcal{C}$ indices (one for each candidate on the ballot), the flags should be a block of $\mathcal{C}$ ones starting at an index associated with the first position on a ballot. If padded, the padding should have value 0. We can check all of these properties with a set of constraints:

* c1.1 Any padding is done with the value 0
* c1.2 The column only contains 0 and 1
* c1.3 Any 1's in the column appear as a block of size $\mathcal{C}$ starting at an appropriate index $i\cong0 \mod \mathcal{C}$ 
* c1.4 The number of print audited ballots is the sum of the column divided by $\mathcal{C}$ 

#### c1.1: Audit column is zero padded

Given a column with content at the first $\mathcal{P}$ indices and 0 padding to $n$, we prove the padding is correct.

The polynomial $Z_\mathsf{head}(X) = \prod_{i=0}^{\mathcal{P}-1}(X-\omega^i)$ zeroes out the first $\mathcal{P}$ indices of the column $\{0,1,\ldots,\mathcal{P}-1\}$ and is strictly non-zero on the remaining $\{\mathcal{P},\mathcal{P+1},\ldots,n-1\}$ indices. 

The product $A(X)\cdot Z_\mathsf{head}(X)$ will be 0 on the first $\mathcal{P}$ indices because of $Z_\mathsf{head}(X)$ and it will be 0 on the remaining indices if and only if $A(X)$ is 0 at these indices, given that $Z_\mathsf{head}(X)$ is not. So if we can show $A(X)\cdot Z_\mathsf{head}(X)$ is 0 at all indices, then $A(X)$ must be padded correctly.

A polynomial that is 0 at all points on the domain is called a "vanishing polynomial." Proving a polynomial vanishes is a very common step in Poly-IOPs. For review, the EA computes a polynomial witness: $Q_{\mathsf{c1.1}}(X)=\frac{A(X)\cdot Z_\mathsf{head}(X)}{X^{n}-1}$.  $Q_{\mathsf{c1.1}}(X)$ can only exist (as a polynomial instead of a general rational function) if the numerator is evenly divided by $X^n-1$ which is 0 on all $n$ indices. Thus the numerator must also be 0 on all $n$ indices. (Equivalently the numerator is a multiple of $(X^n-1)$).

The EA publishes a hiding commitment to $Q_{\mathsf{c1.1}}(X)$. After being published, it receives a challenge value (generated for itself via Fiat-Shamir heuristic) $\zeta$ and it uses KZG to prove the committed polynomials $A(X)$ and $Q_\mathsf{c1.1}(X)$ open to the values $A(\zeta)$ and $Q_\mathsf{c1.1}(\zeta)$ respectively. Finally the verifier checks the identity $Q_{\mathsf{c1.1}}(\zeta)=\frac{A(\zeta)\cdot Z_\mathsf{head}(\zeta)}{\zeta^{n}-1}$. If the relationship holds at $\zeta$ and the challenge value was unpredicatble at the time of committing to $A(X)$ and $Q_\mathsf{c1.1}(X)$, then the relation holds at all points of the polynomial with overwhelming probability by the Schwartz-Zippel lemma.

As a last remark, all relations checked by the verifier can be batched into a single check if they have the form: $\mathrm{relation}=0$. For this reason, we rewrite the check as $A(\zeta)\cdot Z_\mathsf{head}(\zeta)-Q_{\mathsf{c1.1}}(\zeta)\cdot(\zeta^{n}-1)=0$.

> [!Note]
>
> Verifier will need to check $Z_\mathsf{head}(X)$ which is $O(\mathcal{P})$ multiplications. However this can be done pre-election.

#### c1.2: Audit column is binary

A succinct agruemnt that $A(X)$ is binary is a subcomponent of the Poly-IOP range argument given by Boneh et al and is $\mathtt{range}$ in Plonkbook. If $A(X)$ contains only 0 and 1 on the domain, then $(A(X)-0)(A(X)-1)$ will only contain 0 on the domain and is a vanishing polynomial. The EA will argue this polynomial vanishes with the vanishing heuristic.

#### c1.3: Audit column contains 1's in a block

Next the EA will prove that if a ballot is print audited, all of its indices are 1. It cannot be a mix of 0 or 1 (see Ballot 000 below). At first it seems like we could prove all 1's form a continuous block of 1's however the run must also start on the beginning of a ballot (see block spanning ballot 003 and 004 below).

| Ballot ID (Reference) | Audit (Private/Post) | Allowed? |
| --------------------- | -------------------- | -------- |
| 000                   | 0                    |          |
| 000                   | 0                    |          |
| 000                   | 1                    | ❌        |
| 001                   | 0                    |          |
| 001                   | 0                    |          |
| 001                   | 0                    |          |
| 002                   | 1                    | ✅        |
| 002                   | 1                    | ✅        |
| 002                   | 1                    | ✅        |
| 003                   | 0                    |          |
| 003                   | 0                    |          |
| 003                   | 1                    | ❌        |
| 004                   | 1                    | ❌        |
| 004                   | 1                    | ❌        |
| 004                   | 0                    |          |
| Unused                | 0                    |          |

The strategy will be as follows:

* The EA will create a new column where each index is the sum of itself with the $\mathcal{C}$ indices that follow it
* Because the indices that follow the last indices "wraps" to the start of the column, the EA will ensure the tail end of the column is zeroed out
* The EA will then apply a selector vector that zero's out all indices except the first index of each ballot (where the index is congruent to $0 \bmod \mathcal{C}$)
* Finally the EA will show that this vector only contains the value 0 or the value $\mathcal{C}$

First we define a block-sum polynomial such that:

$S_\mathsf{blk}(X)=A(X)+A(\omega X)+\ldots+A(\omega^{\mathcal{C}-1})=\sum_{k=0}^{\mathcal{C}-1}A\bigl(\omega^k X\bigr)$. 

If the first index for ballot $j$ contains a print audit block of 1's, then $S_\mathsf{blk}(\omega^{j\cdot\mathcal{C}})=1+1+\ldots+1=\mathcal{C}$. If it is not audited, it will contain 0. Since by c1.2, $A(X)$ is binary, it is constrained to a value in $[0,\mathcal{C}]$. If it contains any other number between 0 and $\mathcal{C}$, the Audit column is ill-formed. 

Next the EA creates a column that preserves the values at $X = \omega^{j\cdot C}$ for every ballot $0\leq j \leq \mathcal{B}-1$ and zero's out every other value on the domain. The EA can construct a binary vector that is 1 at each position it wants to keep and zero elsewhere on the domain by using a sum of Lagrange bases. Recall a Lagrange basis is defined as:

 $L_i(X)=\prod_{\substack{0\le j<n \\ j\ne i}}
\frac{X - \omega^j}{\omega^i - \omega^j}$ .

It has the following useful property: 

$L_i(\omega^k)=
\begin{cases}
1, & k = i,\\
0, & k \neq i.
\end{cases}$

The EA can build a binary selector polynomial simply by adding together the Lagrange basis at every $\mathcal{C}$-th index. Call it $F_\mathsf{blk}(X)$ for filter by block. 

$F_\mathsf{blk}(X)=\sum_{j=0}^{\lfloor n/\mathcal{C}\rfloor -1} L_{j\mathcal{C}}(X)$

This is a faster to construct ($O(n)$) than specifying the selector as a vector and interpolating a polynomial through it with FFT ($O(n\log{n})$). Because the sum stops at $\lfloor n/\mathcal{C}\rfloor -1$, the tail of $F_\mathsf{blk}(X)$ is left as 0 which will zero out any tailing irregularities due to the wrap. 

We apply the filter by forming $S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)$ and the EA proves the filtered column only contains the value 0 or the value $\mathcal{C}$. This subprotocol is common in PolyIOP protocols (called $\mathtt{lookup1}$ in Plonkbook). The EA forms the polynomial: $(S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)-0)(S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)-\mathcal{C})$. If and only if the print audit is well formed, this polynomial will be vanishing. 

We will not review the vanishing argument again (see c1.1 above) but we follow the same process, just with the above polynomial as the numerator. The final step of this process is to check a quotient polynomial $Q_{c1.3}$ satisfies at random point $\zeta$ the following relationship:

$[S_\mathsf{blk}(\zeta)\cdot F_\mathsf{blk}(\zeta)-0][(S_\mathsf{blk}(\zeta)\cdot F_\mathsf{blk}(\zeta)-\mathcal{C})]-Q_{c1.3}(\zeta)(\zeta^n-1)=0$

Additonaly the verifier needs to check $S_\mathsf{blk}(X)$ and $F_\mathsf{blk}(X)$ are correctly formed. For $S_\mathsf{blk}(X)$, the verifier computes $S_{\rm blk}(\zeta)=\sum_{k=0}^{C-1}A(\zeta\,\omega^k)$ by summing the $\mathcal{C}$ opened values of $A(X)$ which costs $O(\mathcal{C})$ field additions (after the $\mathcal{C}$ KZG openings). 

For $F_\mathsf{blk}(X)$, this polynomial is public and does not depend on voter choices. It can be pre-computed before the election (but after the number of ballots and candidates is known) and checked by the verifier as a sparse sum over $\lfloor n/\mathcal{C}\rfloor$ points.

> [!Note]  
>
> - For the MBKM heuristic, $A(X)$ is opened at $\mathcal{C}$ points so the randomizing polynomial must be degree $\mathcal{C}-1$. $S_\mathsf{blk}$ and $Q_{c1.3}(X)$ are only opened once.
> - Check if $F_\mathsf{blk}(X)$ as a closed form like $\frac{X^u-1}{X^s-1}$

#### c1.4: Audit column matches public audit count

The EA will assert the number of print audits in the election as the integer $\mathsf{Sum}_\mathsf{A}$. Since each print audit ballot contains a block of $\mathcal{C}$ 1's per constraint c1.3, the number of 1's in $A(X)$ must be $\mathsf{Sum}_{\mathsf{A}\times\mathcal{C}}=\mathsf{Sum}_\mathsf{A}\cdot\mathcal{C}$. 

Arguing the sum of a column is a common PolyIOP protocol (called $\mathtt{add2}$ in Plonkbook). The EA will sum $A(X)$ from the end of the column toward the start of the column and place the running sum values into a new helper polynomial called $\mathsf{Acc}_\mathsf{A}(X)$ for accumulator. If constructed correctly, $\mathsf{Acc}_\mathsf{A}(\omega^0)=\mathsf{Sum}_{\mathsf{A}\times\mathcal{C}}.$ The EA will argue the following constraints.

1. For $X=\omega^{n-1}$: $\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)=0$
2. For all $X$ except $X=\omega^{n-1}$: $\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega X)=0$
3. For $X=\omega^{0}$: $\mathsf{Acc}_\mathsf{A}(X)-\mathsf{Sum}_{\mathsf{A}\times\mathcal{C}}=0$

The first two argue the construction of $\mathsf{Acc}_\mathsf{A}(X)$ is correct, while the third argues the sum is correct. The first is that the starting value is correct: $\mathsf{Acc}_\mathsf{A}(\omega^{n-1})=\mathsf{A}(\omega^{n-1})$. Note that because of constraint c1.1, we can run the tally over the padding values which are all 0. The second is that each index in the running tally is correct: $\mathsf{Acc}_\mathsf{A}(X)=\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega X)$, recalling that $\mathsf{Acc}_\mathsf{A}(\omega X)$ is the value below $\mathsf{Acc}_\mathsf{A}(X)$ in a column (equivalently $\mathsf{Acc}_\mathsf{A}(\omega X)$ is column $\mathsf{Acc}_\mathsf{A}(X)$ rotated upward once). A corner case of the second constraint is that it is not true for the last value in the column which is overridden by the first constraint.

The remaining question is how to enforce the qualifiers on $X$. For the first and last constraint, we can open the polynomial at the point of interest however we prefer to prove a polynomial vanishes rather than opening it (even at a single point) because the verifier can batch check constraints of the same format. Instead we use well-known vanishing masks (called $\mathtt{zero1}$ in Plonkbook) that zero out portions of a polynomial.

| Operation          | Input Polynomial | Output Polynomial                           | Output Array                            |
| ------------------ | ---------------- | ------------------------------------------- | --------------------------------------- |
| Zero all           | $P(X)$           | $P(X)\cdot(X^n-1)$                          | $\langle 0,0,0,0,0 \rangle$             |
| Zero first         | $P(X)$           | $P(X)\cdot(X-\omega^0)$                     | $\langle 0,\bot,\bot,\bot,\bot \rangle$ |
| Zero last          | $P(X)$           | $P(X)\cdot(X-\omega^{n-1})$                 | $\langle \bot,\bot,\bot,\bot,0 \rangle$ |
| Zero all but first | $P(X)$           | $P(X)\cdot\frac{(X^n-1)}{(X-\omega^0)}$     | $\langle \bot,0,0,0,0 \rangle$          |
| Zero all but last  | $P(X)$           | $P(X)\cdot\frac{(X^n-1)}{(X-\omega^{n-1})}$ | $\langle 0,0,0,0,\bot \rangle$          |

 The constraints become the following on all values of the domain.

1. $(\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X))\cdot\frac{(X^n-1)}{(X-\omega^{n-1})}=0$
2. $(\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega X))\cdot (X-\omega^{n-1})=0$
3. $(\mathsf{Acc}_\mathsf{A}(X)-\mathsf{Sum}_{\mathsf{A}\times\mathcal{C}})\cdot \frac{(X^n-1)}{(X-\omega^0)}=0$

The EA will then argue these three polynomials are vanishing using the same technique from the previous constraints. 

## Constraint 2: Mark Column

The mark column indicates which ballots were voted. This is denoted by the flag value $1$ in the column. The set of constraints enforce similar properties to constraint 1:

* c2.1 Any padding is done with the value 0
* c2.2 The column only contains 0 and 1
* c2.3 No ballot contains more than one 1 value (no over-voted ballots)
* c2.4 The number of voted ballots is the sum of the column

Indeed since the constraints are so similar, we can reuse the same arguments from constraint 1 with only minor modifications. 

#### c2.1: Mark column is zero padded

The argument here is equivalent to constraint c1.1. As an optimization, the EA could combine $A(X)$ and $M(X)$ using a random linear combination and prove the padding is correct on the combined column. However for simplicity, we will leave it as rerunning c1.1 on $M(X)$ in addition to $A(X)$.

#### c2.2: Mark column is binary

This constraint is the same as c1.2.

#### c2.3: Mark column contains no overvotes

This constraint is the same as c1.3 except the start of each ballot must contain a single 1 rather than $\mathcal{C}$ 1's. Making this substitution, the argument otherwise follows c1.3.

#### c2.4: Mark column matches public mark count

The EA will assert the number of voted ballot in the election as the integer $\mathsf{Sum}_\mathsf{M}$. Thus the number of 1's in $M(X)$ must be $\mathsf{Sum}_\mathsf{M}$. The EA will construct the same argument as constraint c1.4 for $M(X)$ and $\mathsf{Sum}_\mathsf{M}$ replacing $A(X)$ and $\mathsf{Sum}_\mathsf{A}\cdot\mathcal{C}$.

## Constraint 3: Audit and Mark Column Exclusions

In constraint 3, we consider the relationship between the audit and mark columns. The EA will argue that no ballot is both audited and voted. Given all the constraints c1.1--1.4 and c2.1--c2.4, there is already a lot of structure enforced about the audit and mark columns. It is sufficient to merely argue that any row in the audit column with a 1 must have a 0 in the mark column, and vice versa, any row in the mark column with a 1 must have a 0 in the audit column. Rows may have 0 in both but never a 1 in both. The idea is to multiply the columns which is binary AND and argue the product of the columns only contains the value 0 (and thus is a vanishing polynomial).

Proving a polynomial is the product of two polynomials is common in PolyIOP arguments (called $\mathtt{mult1}$ in Plonkbook), where multiplication is the element-wise multiplication (aka Hadamard product) of each element of the columns. The EA will commit to the product polynomial $A(X)\cdot M(X)$ and argue (using the same technique as the other constraints) that the following polynomial is vanishing $\mathsf{Vanish}_\mathsf{c3}(X)=A(X)\cdot M(X)$ if there exists a $Q_\mathsf{c3}(X)$ such that $\mathsf{Zero}(X)=\mathsf{Vanish}_\mathsf{4}(X)-Q_\mathsf{c3}(X)\cdot(X^{n-1}-1)$ is the zero polynomial. 

## Constraint 4: Tally is Correct

The next constraint is proving the tally---the number of votes received for each candidate---is correct. The tally is fully contained in the Marks column and thus $M(X)$. The Candidates column is a convenience but since it is canonical order, the index of any mark in $M(X)$ implies which candidate was voted for. We remark that if Pret a Voter ballots were used instead, this would not be true. Making Zeeperio work with Pret a Voter requires (at least) a modification to this constraint.

Before detailing the constraints, consider again the data layout of the mark column (and $M(X)$) in order to develop some terminology. The length of the column is $n$ which is parameterized to be a perfect power of 2. The first $\mathcal{C}$ indices belong to the first ballot, the next $\mathcal{C}$ to the next ballot, and so forth. We call these *blocks*. The data portion of the mark column contains $\mathcal{B}$ ballots/blocks. After the data portion ends, the remaining indices are padded with 0's (constraint c2.1). Consider continuing to treat the padding in blocks of $\mathcal{C}$ padding bits. We will call these *padding blocks*. If $n$ is not divisible by $\mathcal{C}$, there will be some number of full padding blocks and then there will be some remaining padding bits at the end of the column that do not form a full block. We call these residual bits the *padding tail*.

The votes for the first candidate will start at index 0 and be located at each $\mathcal{C}$-th position in the mark column until the end of the data portion. We will use the term *stride* for skipping ahead $\mathcal{C}$ indices in the table and *stream* for the sequence of marks in every $\mathcal{C}$-th position. The constraint will be very similar to constraint c2.4 where we will accumulate the sum of all the marks, where the key constraint adding the current index to the previous index's accumulated value. Instead of adding it to the previous index, we add it to the index one stride $\mathcal{C}$. 

In a normal sum: $(\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega X))\cdot (X-\omega^{n-1})=0$

In a strided sum: $(\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega^\mathcal{C} X))\cdot \mathrm{mask}=0$

The second change is the "mask" value at the end. In a normal sum, the last index is the starting value and thus the constraint does not hold there, so we zero the index out in this constraint and add another constraint to deal with that index specifically. The tally can include the padding bits because the padding value is zero and do not change the tally. 

In a strided sum, we can do the same thing but we need to zero out the last $\mathcal{C}$ indices. This means some streams start from the padding tail and other start from the last padding block, but this does not cause any issues, the former streams will just be longer by one zeroed value.

1.  For $\omega^{n-1-\mathcal{C}}\leq X\leq \omega^{n-1}$: $\mathsf{Acc}_\mathsf{A}(T)-\mathsf{A}(X)=0$
2. For all $X$ except $\omega^{n-1-\mathcal{C}}\leq X\leq \omega^{n-1}$: $\mathsf{Acc}_\mathsf{A}(X)-\mathsf{A}(X)+\mathsf{Acc}_\mathsf{A}(\omega^\mathcal{C} X)=0$
3. Tally check
   1. For $X=\omega^{0}$: $\mathsf{Acc}_\mathsf{Vote}(X)-\mathsf{Tally}_\mathsf{c_0}=0$
   2. For $X=\omega^{1}$: $\mathsf{Acc}_\mathsf{Vote}(X)-\mathsf{Tally}_\mathsf{c_1}=0$
   3. $\ldots$
   4. For $X=\omega^{\mathcal{C}-1}$: $\mathsf{Acc}_\mathsf{Vote}(X)-\mathsf{Tally}_\mathsf{c_{(\mathcal{C}-1)}}=0$ 

The constraints become the following on all values of the domain. 

3. $(\mathsf{Acc}_\mathsf{Vote}(X)-\mathsf{M}(X)) \cdot \prod_{i=0}^{\mathcal{C}-1} (X - \omega^{n-1 - i}) = 0$
2. $(\mathsf{Acc}_\mathsf{Vote}(X) - \mathsf{M}(X) + \mathsf{Acc}_\mathsf{Vote}(\omega^\mathcal{C} X)) \cdot \left(\prod_{i=0}^{\mathcal{C}-1} \frac{X^n - 1}{X - \omega^{n-1 - i}} \right) = 0$

3. For each $c \in \{0, \ldots, \mathcal{C}-1\}$:
   $(\mathsf{Acc}_\mathsf{Vote}(X) - \mathsf{Tally}_{c}) \cdot \frac{X^n - 1}{X - \omega^{c}} = 0$

The EA will then argue these three polynomials are vanishing using the same technique from the previous constraints. 

## Constraint 5: Voter Checks

We now turn to various checks done by the voter. The first two are checking a print audit ballot and checking a voted ballot. The third happens if the EA is alleged to have returned the wrong confirmation code for a ballot. The voter can challenge the confirmation code by providing what they believe is the correct confirmation code. If this is in fact a valid confirmation code on the ballot, it is indicative on an error or attack. If it does not match any code on the ballot, it may be a voter error or a spurious dispute attempting to cast doubt the election outcome. Recall also that Scantegrity II ballots have a human readable paper audit trail so disputes can also be investigated manually. Finally, all these measures should be augmented with standard risk limit audits of the paper ballots.

#### c5.1 Print Audit

The voter provides a ballot ID. This is mapped to the block of $\mathcal{C}$ indices corresponding to the ballot. The EA opens $A(X)$ and $M(X)$ at each index associated with the ballot ID using a KZG batch opening. 

#### c5.2 Receipt Check

The receipt check cannot be accomplished the same way as constraint c5.1. If a voter asks for their confirmation code and the EA reveals it at index $i$, the map between $i$ and which candidate they voted for is made public. A naive approach is not receipt-free.

Instead the EA needs to show the confirmation code and ballot mark are within one of the indices associated with ballot $j$ but not which specific index. This is less straight-forward than the other constraints in Zeeperio but it is still accomplishable. In fact, we developed and compared 3 techniques that each accomplish the goal using different advanced Poly-IOP gadgets.

1. Shuffles: as in the original Eperio, the EA could create a ballot ID column and commit to it. It can then shuffle the Ballot, Code, and Mark columns with the same permutation and prove they are correct. Then the EA opens the shuffled columns at the same index where the receipt ends up, showing voter mark for that ballot number has that code. Because of constraint c2.3, it does not have to open the locations of the unmarked positions on the ballot. The ballot ID column and the shuffled columns can be reused for each receipt check, so the marginal prover cost for the EA is three openings per check.
2. Selector vector: the EA could create a ballot ID column and commit to it. Then it can create a selector vector that is contains all 0 with a single 1 at the location of the voter's mark, commit to it, and prove it is correct (it is binary and sums to 1). It can then multiply the selector with the Ballot, Code, and Mark columns to zero out all other data. Finally to hid the index, it can prove the sum of these columns are, respectively, the ballot id, the code, and 1 (the fact that this code was marked).
3. Lookups: the EA could treat the Ballot, Code, and Mark columns as a lookup table. It could take the values it asserted to the voter {Ballot, Code, 1} and prove this appears in the lookup table.

All three have expensive subprotocols: (1) a permutations argument, (2) creating a custom selector vector for each checking voter via interpolation or multiplying Lagrange bases, and (3) again a permutation argument as look argument (e.g., plookup) use permutations under the hood. The major distinction is that (1) requires only a single permutation that can be reused for each voter check, while (2) requires a custom selection vector per voter and (3) requires a custom lookup (and thus custom permutation) per voter. For these reasons, we settle on (1) as the ideal protocol. 

The shuffle argument is adapted from the permutation argument in Plonk. There, a single vector is proven to be a permutation of another by comparing products over $(r - v_i)$ terms for a random challenge $r$. In Zeeperio, we extend this to a joint shuffle of multiple columns. We first reduce each row $(b_i, c_i, m_i)$ to a single field element using a random linear combination:

$$
v_i = b_i + \alpha \cdot c_i + \alpha^2 \cdot m_i
$$

and likewise for the shuffled version $v'_i$. We then prove that the multisets $\{v_i\}$ and $\{v'_i\}$ are equal by showing that the product over $(r - v_i)$ matches that of $(r - v'_i)$. The commitments to the original and permuted columns are hiding, and the challenge values $\alpha$ and $r$ are drawn after the commitments are published, ensuring soundness and zero-knowledge. The EA proves the product argument using a grand product polynomial with suitable boundary and transition constraints. Since this argument reveals nothing about the permutation $\pi$, it preserves voter privacy and receipt-freeness.

#### c5.3 Dispute Resolution

If a voter believes their confirmation code is incorrect—for example, the code printed on their paper ballot does not match what was returned online—they may raise a dispute. The EA must then prove that the disputed code does not appear on the ballot associated with the voter's serial number.

In Zeeperio, this is accomplished without revealing any of the codes on the ballot. The voter provides:

- Their ballot ID $b$
- The disputed confirmation code $c$
- A selector vector $S(X)$ indicating the $\mathcal{C}$ indices corresponding to their ballot

Since ballots are laid out in canonical order, the EA verifies that $S(X)$ is a binary vector with 1’s exactly at indices $b \cdot \mathcal{C},\ b \cdot \mathcal{C} + 1,\ \dots,\ b \cdot \mathcal{C} + (\mathcal{C} - 1)$ and 0’s elsewhere. This check is public and does not require a proof—the selector vector is simply validated against the ballot ID.

The EA then constructs a new helper vector $D(X)$ of size $n$, which flags whether each committed code $C_i$ matches the disputed code $c$. For each $i \in \{0, \dots, n-1\}$, the EA sets:
$$
D_i = 1 - (C_i - c)^{q - 1}
$$

This equality test is done entirely within the prover's workspace. It relies on Fermat’s little theorem: if $C_i = c$, then $(C_i - c) = 0$ and the expression becomes $1$; otherwise, $(C_i - c)^{q - 1} = 1$ and the expression becomes $0$. This operation does not reveal any of the $C_i$ values and can be computed without committing to $D(X)$.

To ensure that $D(X)$ is computed correctly from the committed code column $C(X)$ and the disputed code $c$, the EA commits to $D(X)$ and proves that each $D_i$ satisfies the pointwise relation:
$$
D_i = 1 - (C_i - c)^{q - 1}
$$
This is done via a standard polynomial identity check. After committing to $D(X)$, the EA receives a random challenge point $\zeta$ generated using the Fiat-Shamir heuristic. The EA then opens both $C(\zeta)$ and $D(\zeta)$, and the verifier checks:
$$
D(\zeta) \stackrel{?}{=} 1 - (C(\zeta) - c)^{q - 1}
$$
If the identity holds at $\zeta$, then by the Schwartz-Zippel lemma, the relation holds across the entire domain with high probability. This ensures the correctness of $D(X)$ without leaking which entries equal the disputed code or how many matches occurred.

To prove the disputed code does not appear on the ballot, the EA computes the scalar inner product:
$$
z = \sum_{i = 0}^{n - 1} S_i \cdot D_i
$$

This dot product isolates any equality matches between $c$ and the ballot codes. The EA commits to $z$ and proves that $z = 0$ using a simple opening. This confirms that $c$ does not appear in the selected indices without revealing which codes were on the ballot.
