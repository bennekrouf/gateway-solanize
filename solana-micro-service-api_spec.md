# Solana Gateway API Specification

## 1. Health Check

### GET /api/v1/health
**Description**: Service health check  
**Input**: None  
**Output**:
```json
{
  "success": true,
  "data": "OK",
  "error": null
}
```

## 2. Wallet Balance

### POST /api/v1/balance
**Description**: Get SOL balance for any public key  
**Input**:
```json
{
  "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
    "balance": 2.5,
    "token": "SOL"
  },
  "error": null
}
```

## 3. SOL Transfer Preparation

### POST /api/v1/transaction/prepare
**Description**: Create unsigned SOL transfer transaction  
**Input**:
```json
{
  "payer_pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
  "to_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "amount": 1.5
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "unsigned_transaction": "base64_encoded_transaction",
    "from": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
    "to": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "amount": 1.5,
    "required_signers": ["6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46"],
    "recent_blockhash": "6DPp9aRRX1SZevsZWqWk8jbqf3ELwxEURgDTMc9EynwW"
  },
  "error": null
}
```

## 4. Transaction Submission

### POST /api/v1/transaction/submit
**Description**: Submit signed transaction to network  
**Input**:
```json
{
  "signed_transaction": "base64_encoded_signed_transaction"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "signature": "5VfydnLy9VjT8cZb3FJ9Q2X5xJZ1t1t2K3Q7B8P9A6WzDxMcE1FhGjK8P2Q9VfydnLy9VjT8cZb3FJ9",
    "status": "submitted"
  },
  "error": null
}
```

## 5. Token Swap Preparation

### POST /api/v1/swap/prepare
**Description**: Prepare unsigned Jupiter swap transaction  
**Input**:
```json
{
  "payer_pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
  "from_token": "SOL",
  "to_token": "USDC",
  "amount": 1.0
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "unsigned_transaction": "base64_encoded_transaction",
    "quote_info": {
      "expected_output": 245.67,
      "price_impact": 0.05,
      "route_steps": 1
    },
    "required_signers": ["6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46"],
    "recent_blockhash": "6DPp9aRRX1SZevsZWqWk8jbqf3ELwxEURgDTMc9EynwW"
  },
  "error": null
}
```

## 6. Token Price

### POST /api/v1/price
**Description**: Get current token price in USD  
**Input**:
```json
{
  "token": "SOL"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "token": "SOL",
    "price": 245.67,
    "currency": "USD"
  },
  "error": null
}
```

## 7. Token Search

### POST /api/v1/tokens/search
**Description**: Search tokens by symbol, name, or mint address  
**Input**:
```json
{
  "query": "ray"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "tokens": [
      {
        "symbol": "RAY",
        "name": "Raydium",
        "address": "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
        "decimals": 6
      },
      {
        "symbol": "RAYP",
        "name": "Raydium Protocol",
        "address": "5VfydnLy9VjT8cZb3FJ9Q2X5xJZ1t1t2K3Q7B8P9A6WzD",
        "decimals": 9
      }
    ],
    "count": 2
  },
  "error": null
}
```

## 8. Wallet Token Holdings

### POST /api/v1/wallet/tokens
**Description**: List all SPL tokens in wallet with balances and USD values  
**Input**:
```json
{
  "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
    "tokens": [
      {
        "symbol": "SOL",
        "name": "Solana",
        "mint": "So11111111111111111111111111111111111111112",
        "balance": 2.5,
        "decimals": 9,
        "usd_value": 614.18
      },
      {
        "symbol": "USDC",
        "name": "USD Coin",
        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "balance": 1500.0,
        "decimals": 6,
        "usd_value": 1500.0
      }
    ],
    "total_tokens": 2
  },
  "error": null
}
```

## 9. Transaction History

### POST /api/v1/transactions/history
**Description**: Get transaction history for wallet with pagination  
**Input**:
```json
{
  "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
  "limit": 20,
  "before": "5VfydnLy9VjT8cZb3FJ9Q2X5xJZ1t1t2K3Q7B8P9A6WzDxMcE1FhGjK8P2Q9VfydnLy9VjT8cZb3FJ9"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
    "transactions": [
      {
        "signature": "5VfydnLy9VjT8cZb3FJ9Q2X5xJZ1t1t2K3Q7B8P9A6WzDxMcE1FhGjK8P2Q9VfydnLy9VjT8cZb3FJ9",
        "status": "Success",
        "confirmation_status": "Finalized",
        "block_time": 1724241644,
        "slot": 295648123,
        "fee": 0.000005,
        "amount": 1.5,
        "token_symbol": "SOL",
        "transaction_type": "Transfer",
        "error": null
      }
    ],
    "total_count": 1,
    "has_more": false,
    "next_before": null
  },
  "error": null
}
```

## 10. Pending Transactions

### POST /api/v1/transactions/pending
**Description**: Get pending/unconfirmed transactions for wallet  
**Input**:
```json
{
  "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46"
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "pubkey": "6xB88LrD7oBhr7icEkzT2JQBu3fSFZ8uWVUaYN4vr46",
    "pending_transactions": [
      {
        "signature": "3XbCjEv8Skk59S5iCNLY3QrkX6R4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R4k3Dyjz",
        "status": "Pending",
        "confirmation_status": "Processed",
        "block_time": 1724241700,
        "slot": 295648200,
        "fee": 0.000005,
        "amount": 0.5,
        "token_symbol": "SOL",
        "transaction_type": "Transfer",
        "error": null
      }
    ],
    "count": 1
  },
  "error": null
}
```

## Error Response Format

All endpoints return errors in this format:
```json
{
  "success": false,
  "data": null,
  "error": "Error description here"
}
```

## Enum Values

### TransactionStatus
- `"Success"` - Transaction completed successfully
- `"Failed"` - Transaction failed
- `"Pending"` - Transaction waiting for confirmation

### ConfirmationStatus  
- `"Processed"` - Transaction processed but not confirmed
- `"Confirmed"` - Transaction confirmed by cluster
- `"Finalized"` - Transaction finalized (irreversible)

### TransactionType
- `"Transfer"` - SOL transfer
- `"TokenTransfer"` - SPL token transfer  
- `"Swap"` - Token swap via Jupiter
- `"Unknown"` - Unknown transaction type