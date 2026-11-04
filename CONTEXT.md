# AnomaPay ERC20 Resource

The resource logics of AnomaPay ERC20 resources, with which an action of the Anoma Resource Machine (ARM) wraps, transfers and unwraps ERC20 tokens.

## Language

**AnomaPay ERC20 resource**:
A resource whose resource logic is the ERC20 resource logic, and which ERC20 tokens in the ERC20 forwarder back. Say "ERC20 resource" after the first mention.
_Avoid_: token transfer resource, shielded resource

**ERC20 resource logic**:
The resource logic of the ERC20 resources that the ERC20 forwarder accepts, in the crates `anomapay_erc20_*`.

**Emergency-migrating ERC20 resource logic**:
The variant of the ERC20 resource logic that also makes the migrate call of a hard migration, in the crates `anomapay_emergency_migrating_erc20_*`.

**Legacy version**:
The ERC20 resource logic that the legacy ERC20 forwarder accepts, with the logic ref `bc123236…`.

**Resource**:
A unit of state with a quantity. A **persistent** resource stays until a later transaction consumes it. An **ephemeral** resource exists only in one transaction.

**Tag / Commitment / Nullifier**:
The tag of a resource in a transaction is its nullifier if the transaction consumes it, else its commitment. Only a holder of the nullifier key of a resource can calculate its nullifier.

**Commitment tree**:
The Merkle tree of the commitments of all resources, which the protocol adapter keeps. A **historical root** is a root of the commitment tree that the protocol adapter stores.

**Resource logic / Logic ref**:
The circuit that decides when a transaction can create or consume a resource. Its logic ref identifies its code.

**Label ref**:
The SHA-256 hash of the forwarder address and the token address of an ERC20 resource.

**Value ref**:
For a persistent ERC20 resource, the SHA-256 hash of the authorization key and the encryption key of its owner. For the ephemeral resource of an unwrap, the address of the receiver.

**Authorization key / Authorization signature**:
The key of the owner of a persistent ERC20 resource, and the signature with this key over the action tree root, which a transaction needs to consume the resource.

**Encryption key**:
The key of the owner to which the logic encrypts the resource payload of a created persistent ERC20 resource.

**Resource payload**:
The encryption of a created persistent ERC20 resource, its forwarder address and its token address to the encryption key of its owner.

**Discovery payload**:
A ciphertext for the discovery key of the owner of a created persistent ERC20 resource. With fuzzy message detection, an indexer uses it to find the resources of a user faster. The logic does not check it.

**App data / Deletion criterion**:
The app data of a resource holds four lists of blobs: the resource payload, the discovery payload, the external payload and the application payload. The deletion criterion of a blob is `Never` or `Immediately`. The protocol adapter emits each blob with `Never` as an event. Each blob of the external payload is an external call, whatever its deletion criterion.

**External payload / External call**:
The app data of a resource that carries calls to forwarders. The protocol adapter makes each external call when it processes the resource.

**Action tree root**:
The root of a Merkle tree over the tags of an action, in the order of its list.

**Wrap / Unwrap / Transfer**:
A wrap consumes an ephemeral ERC20 resource whose call has the forwarder take tokens from their owner through Permit2. An unwrap creates an ephemeral ERC20 resource whose call has the forwarder send tokens to a receiver. A transfer consumes and creates persistent ERC20 resources, and it makes no call.

**ERC20 forwarder**:
The contract that holds the tokens that back the ERC20 resources, and that the protocol adapter calls for the external payload of an ephemeral ERC20 resource.

**Protocol adapter**:
The contract that verifies transactions on an EVM chain and makes the external calls of their resources.

**Hard migration / Trigger**:
The process in which users replace their unspent resources of a denied logic ref with resources of a new logic ref. The trigger is the consumed ephemeral resource whose migrate call lists the old resources. The code calls it emergency migration.

**Logic ref denylist**:
Two lists of logic refs that the protocol adapter keeps, one for created resources and one for consumed resources. To _deprecate_ a logic ref, the owner of the protocol adapter adds it to the list for created resources, so transactions can consume its resources but not create them. To _deny_ it, the owner adds it to both lists.

**Soft migration**:
The process in which users convert their ERC20 resources of a deprecated logic ref into ERC20 resources of the logic ref that the ERC20 forwarder accepts, through aliases of a kind tree.
_Avoid_: migration (on its own)

**Legacy protocol adapter / Galileo upgrade**:
The legacy protocol adapter is the immutable protocol adapter that a chain used before the Galileo upgrade. The Galileo upgrade replaces it with the protocol adapter, once for each chain.

**Legacy ERC20 forwarder / Legacy-forwarder resource**:
The immutable ERC20 forwarder of the legacy protocol adapter, and an ERC20 resource whose label ref names it.

**Kind / Kind base / Kind tree**:
The kind of a resource is the hash to curve of its logic ref and its label ref. Its kind base is the point that the compliance circuit multiplies by its quantity: the kind, or the point that a kind tree gives the kind. A kind tree is a Merkle tree of entries, each of which gives a kind a kind base. Two kinds with the same kind base are **aliases**, so their resources balance against each other.
_Avoid_: kind point

**Compliance unit / Aggregation proof / Delta proof**:
Each action has one compliance unit. Its compliance proof shows the **compliance checks**: the in-circuit checks that the action follows the rules of the ARM. The aggregation proof aggregates the compliance proofs and the resource logic proofs of a transaction into one proof, so the protocol adapter verifies only the aggregation proof and the delta proof. The delta proof shows that a transaction balances: for each kind base, the consumed and the created quantities are equal.

**In-circuit check**:
A check that a circuit makes: a proof of the circuit is valid only if the check holds.

**Out-of-circuit check**:
A check outside the circuits, for example a check that the protocol adapter, the forwarder or Permit2 makes on chain.
