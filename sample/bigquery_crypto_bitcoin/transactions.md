# transactions

## Description

All transactions.  
Data is exported using https://github.com/blockchain-etl/bitcoin-etl  


## Columns

| Name | Type | Default | Nullable | Children | Parents | Description |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| hash | STRING |  | false | [inputs](inputs.md) [outputs](outputs.md) |  | The hash of this transaction |
| size | INTEGER |  | true |  |  | The size of this transaction in bytes |
| virtual_size | INTEGER |  | true |  |  | The virtual transaction size (differs from size for witness transactions) |
| version | INTEGER |  | true |  |  | Protocol version specified in block which contained this transaction |
| lock_time | INTEGER |  | true |  |  | Earliest time that miners can include the transaction in their hashing of the Merkle root to attach it in the latest block of the blockchain |
| block_hash | STRING |  | false |  | [blocks](blocks.md) | Hash of the block which contains this transaction |
| block_number | INTEGER |  | false |  |  | Number of the block which contains this transaction |
| block_timestamp | TIMESTAMP |  | false |  |  | Timestamp of the block which contains this transaction |
| block_timestamp_month | DATE |  | false |  |  | Month of the block which contains this transaction |
| input_count | INTEGER |  | true |  |  | The number of inputs in the transaction |
| output_count | INTEGER |  | true |  |  | The number of outputs in the transaction |
| input_value | NUMERIC |  | true |  |  | Total value of inputs in the transaction |
| output_value | NUMERIC |  | true |  |  | Total value of outputs in the transaction |
| is_coinbase | BOOLEAN |  | true |  |  | true if this transaction is a coinbase transaction |
| fee | NUMERIC |  | true |  |  | The fee paid by this transaction |
| inputs | RECORD |  | true |  |  | Transaction inputs |
| inputs.index | INTEGER |  | false |  |  | 0-indexed number of an input within a transaction |
| inputs.spent_transaction_hash | STRING |  | true |  |  | The hash of the transaction which contains the output that this input spends |
| inputs.spent_output_index | INTEGER |  | true |  |  | The index of the output this input spends |
| inputs.script_asm | STRING |  | true |  |  | Symbolic representation of the bitcoin's script language op-codes |
| inputs.script_hex | STRING |  | true |  |  | Hexadecimal representation of the bitcoin's script language op-codes |
| inputs.sequence | INTEGER |  | true |  |  | A number intended to allow unconfirmed time-locked transactions to be updated before being finalized; not currently used except to disable locktime in a transaction |
| inputs.required_signatures | INTEGER |  | true |  |  | The number of signatures required to authorize the spent output |
| inputs.type | STRING |  | true |  |  | The address type of the spent output |
| inputs.addresses | STRING |  | true |  |  | Addresses which own the spent output |
| inputs.value | NUMERIC |  | true |  |  | The value in base currency attached to the spent output |
| outputs | RECORD |  | true |  |  | Transaction outputs |
| outputs.index | INTEGER |  | false |  |  | 0-indexed number of an output within a transaction used by a later transaction to refer to that specific output |
| outputs.script_asm | STRING |  | true |  |  | Symbolic representation of the bitcoin's script language op-codes |
| outputs.script_hex | STRING |  | true |  |  | Hexadecimal representation of the bitcoin's script language op-codes |
| outputs.required_signatures | INTEGER |  | true |  |  | The number of signatures required to authorize spending of this output |
| outputs.type | STRING |  | true |  |  | The address type of the output |
| outputs.addresses | STRING |  | true |  |  | Addresses which own this output |
| outputs.value | NUMERIC |  | true |  |  | The value in base currency attached to this output |

## Relations

![er](transactions.svg)
