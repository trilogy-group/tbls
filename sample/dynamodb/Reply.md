# Reply

## Description

## Attributes

| Name | Type | Default | Nullable |
| ---- | ---- | ------- | -------- |
| Id | S |  | false |
| ReplyDateTime | S |  | false |
| PostedBy | S |  | false |

## Primary Key

| Name | Type | Definition |
| ---- | ---- | ---------- |
| Primary Key | Partition key and sort key | [{ AttributeName: "Id", KeyType: "HASH" } { AttributeName: "ReplyDateTime", KeyType: "RANGE" }] |

## Secondary Indexes

| Name | Definition |
| ---- | ---------- |
| PostedBy-index | LocalSecondaryIndex { [{ AttributeName: "Id", KeyType: "HASH" } { AttributeName: "PostedBy", KeyType: "RANGE" }], { ProjectionType: "KEYS_ONLY" } } |

## Relations

![er](Reply.svg)
