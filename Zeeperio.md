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

Those familiar with the Poly-IOP model will know that prover efficiency is improved by encoding column elements at polynomial indices that iterate over a multiplicative subgroup (this enables interpolation via FFT) and that elliptic curve parameters are often chosen to ensure many options for such subgroups are available. The most common approach in curve design is ensuring subgroups of sizes ${2,2^2,2^3,\ldots,2^\kappa}$ for a reasonably large $\kappa$ ($\kappa=28$ for alt_bls and $\kappa=32$ for BLS12-384). The bottom line is to commit to a column of, say, size 1000, you need to actually commit to a column of size 1024 (the size rounded up to the nearest power of 2). 

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

A succinct agruemnt that $A(X)$ is binary is a subcomponent of the Poly-IOP range argument given by Boneh et al. However we will not actually need to explicitly prove this for $A(X)$ because later we will see that constraint 3 ends up subsuming this constraint. So we will return to this when discussing constraint 3. 

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

* We will create a new column where each index is the sum of itself with the $\mathcal{C}$ indices that follow it
* Because the indices that follow the last indices "wraps" to the start of the column, we will ensure the tail end of the column is zeroed out
* We will then apply a selector vector that zero's out all indices except the first index of each ballot (where the index is congruent to $0 \bmod \mathcal{C}$)
* Finally we will show that this vector only contains the value 0 or the value $\mathcal{C}$

First we define a block-sum polynomial such that:

$S_\mathsf{blk}(X)=A(X)+A(\omega X)+\ldots+A(\omega^{\mathcal{C}-1})=\sum_{k=0}^{\mathcal{C}-1}A\bigl(\omega^k X\bigr)$. 

If ballot $j$ contains a print audit block of 1's, then $S_\mathsf{blk}(\omega^{j\cdot\mathcal{C}})=1+1+\ldots+1=\mathcal{C}$. If it is not audited, it will contain 0. If it contains any other number, the Audit column is ill-formed.

Next we want to create a column that preserves the values at $X = \omega^{j\cdot C}$ for every ballot $0\leq j \leq \mathcal{B}-1$ and zero's out every other value on the domain. We can construct a binary vector that is 1 at each position we want to keep and zero elsewhere on the domain by using a sum of Lagrange bases. Recall a Lagrange basis is defined as:

 $L_i(X)=\prod_{\substack{0\le j<n \\ j\ne i}}
\frac{X - \omega^j}{\omega^i - \omega^j}$ .

It has the following useful property: 

$L_i(\omega^k)=
\begin{cases}
1, & k = i,\\
0, & k \neq i.
\end{cases}$

We can build a binary selector polynomial simply by adding together the Lagrange basis at every $\mathcal{C}$-th index. Call it $F_\mathsf{blk}(X)$ for filter by block. 

$F_{\rm blk}(X)
\;=\;
\sum_{j=0}^{\lfloor n/\mathcal{C}\rfloor -1}L_{\,j\mathcal{C}}(X),$

This is a faster to construct ($O(n)$) than specifying the selector as a vector and interpolating a polynomial through it with FFT ($O(n\log{n})$). Because the sum stops at $\lfloor n/\mathcal{C}\rfloor -1$, we leave the tail of $F_\mathsf{blk}(X)$ as 0.

We apply the filter by forming $S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)$ and the EA proves the filtered column only contains the value 0 or the value $\mathcal{C}$ by forming the polynomial: $(S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)-0)(S_\mathsf{blk}(X)\cdot F_\mathsf{blk}(X)-\mathcal{C})$. If and only if the print audit is well formed, this polynomial will be vanishing. 

We will not review the vanishing argument again (see c1.1 above) but we follow the same process, just with the above polynomial as the numerator. The final step of this process is to check a quotient polynomial $Q_{c1.3}$ satisfies at random point $\zeta$ the following relationship:

$[S_\mathsf{blk}(\zeta)\cdot F_\mathsf{blk}(\zeta)-0][(S_\mathsf{blk}(\zeta)\cdot F_\mathsf{blk}(\zeta)-\mathcal{C})]-Q_{c1.3}(\zeta)(\zeta^n-1)=0$

Additonaly the verifier needs to check $S_\mathsf{blk}(X)$ and $F_\mathsf{blk}(X)$ are correctly formed. For $S_\mathsf{blk}(X)$, the verifier computes $S_{\rm blk}(\zeta)=\sum_{k=0}^{C-1}A(\zeta\,\omega^k)$ by summing the $\mathcal{C}$ opened values of $A(X)$ which costs $O(\mathcal{C})$ field additions (after the $\mathcal{C}$ KZG openings). 

For $F_\mathsf{blk}(X)$, this polynomial is public and does not depend on voter choices. It can be pre-computed before the election (but after the number of ballots and candidates is known) and checked by the verifier as a precomputed sparse sum over $\lfloor n/\mathcal{C}\rfloor$ points.

> [!Note]  
>
> - For the MBKM heuristic, $A(X)$ is opened at $\mathcal{C}$ points so the randomizing polynomial must be degree $\mathcal{C}-1$. $S_\mathsf{blk}$ and $Q_{c1.3}(X)$ are only opened once.
