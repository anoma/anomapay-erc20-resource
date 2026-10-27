# `anomapay_link_witness`

Witness data and resource-logic constraints for the AnomaPay link resource: an ephemeral
resource whose label commits to the terms of an order. The action that consumes a link must
create, at the link's own position, a persistent resource of the output kind owned by the
recipient with at least the minimum quantity. Creating a link adds a `BlockTimeForwarder` call
whose expected answer fails from the deadline in its terms on, so the protocol adapter then
reverts any transaction with the user's action.
