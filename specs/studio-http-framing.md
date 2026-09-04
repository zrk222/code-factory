# Spec: Studio HTTP framing

## MUST - Connection safety

### Requirements (EARS)

- If `REQ_POST_EARLY_REJECTION` rejects a POST before consuming its declared body because the route is unknown, the session token is invalid, or the body length is outside 1 through 1048576 bytes, it shall return `Connection: close` and close that connection after the error response.
- When `REQ_POST_RECOVERY` sends a valid request after an early rejection through the same HTTP client, it shall receive the expected application response rather than a framing error or Windows socket abort.
- While `REQ_POST_AUTHORITY` returns an early rejection response, it shall create zero workspace artifacts and return execution, publication and deployment authority as false.

### Acceptance criteria

```gherkin
Scenario: Unauthorized body cannot corrupt the next request
  Given REQ_POST_EARLY_REJECTION receives an unauthorized POST with a non-empty body
  When the server returns its 403 response
  Then REQ_POST_EARLY_REJECTION returns Connection close before the client sends another request

Scenario: Client reconnects for the next bounded request
  Given REQ_POST_RECOVERY has received the early rejection response
  When the client sends an authorized oversized request
  Then REQ_POST_RECOVERY returns status 413 without a socket abort

Scenario: Rejection remains side-effect free
  Given REQ_POST_AUTHORITY rejects the request before reading its body
  When the response is complete
  Then REQ_POST_AUTHORITY creates zero workspace artifacts and grants no execution publication or deployment authority
```

## Non-goals

The system shall not add a remote listener, credential flow, provider request, publication operation or deployment operation.
