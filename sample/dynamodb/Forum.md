# Forum

## Description

## Attributes

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| Name | S |  | false | [Thread](Thread.md) |  |  |

## Primary Key

| Name | Type | Definition |
| ---- | ---- | ---------- |
| Primary Key | Partition key | [{ AttributeName: "Name", KeyType: "HASH" }] |

## Relations

![er](Forum.svg)
