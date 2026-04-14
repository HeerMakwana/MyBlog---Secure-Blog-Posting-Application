# Error Response Format Table

| Field | Type | Description | Example |
|---|---|---|---|
| success | boolean | Operation result flag | false |
| message | string | User-safe error message only | "Invalid credentials" |
| errorCode | string | Stable error identifier for clients | "INVALID_CREDENTIALS" |

## Example Response

```json
{
  "success": false,
  "message": "An error occurred. Please try again",
  "errorCode": "INTERNAL_SERVER_ERROR"
}
```
