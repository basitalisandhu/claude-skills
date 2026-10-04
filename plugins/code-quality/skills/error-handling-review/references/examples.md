# Policy examples per layer

## Python

```python
# errors.py: one small hierarchy
class AppError(Exception):
    status = 500
    code = "internal"

class InvalidInput(AppError):
    status, code = 400, "invalid_input"

class NotFound(AppError):
    status, code = 404, "not_found"

class UpstreamError(AppError):
    status, code = 503, "upstream_unavailable"

# clients/billing.py: raise near the call, with context, timeouts and bounded retries
import httpx

def charge(order_id: str, amount_cents: int) -> dict:
    try:
        r = _client.post("/charges", json={"order": order_id, "amount": amount_cents},
                         headers={"Idempotency-Key": order_id}, timeout=httpx.Timeout(10.0, connect=3.0))
        r.raise_for_status()
        return r.json()
    except httpx.TimeoutException as e:
        raise UpstreamError(f"billing timed out charging order {order_id}") from e
    except httpx.HTTPStatusError as e:
        if e.response.status_code >= 500:
            raise UpstreamError(f"billing returned {e.response.status_code} for order {order_id}") from e
        raise InvalidInput(f"billing rejected order {order_id}: {e.response.json().get('message', '')}") from e

# api/app.py: handle once, at the boundary
@app.exception_handler(AppError)
async def app_error_handler(request, exc: AppError):
    log = logger.warning if exc.status < 500 else logger.exception
    log("request failed", extra={"code": exc.code, "request_id": request.state.request_id})
    return JSONResponse({"error": exc.code, "message": str(exc), "request_id": request.state.request_id}, status_code=exc.status)
```

Retry with a cap (`tenacity`): `@retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=0.2, max=2), retry=retry_if_exception_type(UpstreamError), reraise=True)`.

## TypeScript

```ts
// errors.ts
export class AppError extends Error { constructor(msg: string, public code = "internal", public status = 500, options?: { cause?: unknown }) { super(msg, options); } }
export class InvalidInput extends AppError { constructor(msg: string, cause?: unknown) { super(msg, "invalid_input", 400, { cause }); } }
export class UpstreamError extends AppError { constructor(msg: string, cause?: unknown) { super(msg, "upstream_unavailable", 503, { cause }); } }

// clients/billing.ts
export async function charge(orderId: string, amountCents: number) {
  const res = await fetch(`${BASE}/charges`, { method: "POST", body: JSON.stringify({ orderId, amountCents }),
    headers: { "Idempotency-Key": orderId }, signal: AbortSignal.timeout(10_000) }).catch((e) => {
    throw new UpstreamError(`billing unreachable for order ${orderId}`, e);
  });
  if (res.status >= 500) throw new UpstreamError(`billing returned ${res.status} for order ${orderId}`);
  if (!res.ok) throw new InvalidInput(`billing rejected order ${orderId}`);
  return res.json();
}

// server.ts: one boundary handler (Express)
app.use((err: unknown, req, res, _next) => {
  const e = err instanceof AppError ? err : new AppError("unexpected error", "internal", 500, { cause: err });
  (e.status >= 500 ? log.error : log.warn)({ err: e, requestId: req.id }, "request failed");
  res.status(e.status).json({ error: e.code, message: e.status >= 500 ? "internal error" : e.message, requestId: req.id });
});
process.on("unhandledRejection", (reason) => { log.fatal({ reason }, "unhandled rejection"); process.exit(1); });
```

## Go

```go
// wrap with context near the call; check with errors.Is / errors.As at the boundary
var ErrUpstream = errors.New("upstream unavailable")

func (c *Billing) Charge(ctx context.Context, orderID string, cents int) (*Charge, error) {
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    resp, err := c.do(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("charge order %s: %w", orderID, errors.Join(ErrUpstream, err))
    }
    ...
}

// handler
func writeError(w http.ResponseWriter, r *http.Request, err error) {
    var in *InvalidInput
    switch {
    case errors.As(err, &in):
        http.Error(w, in.Error(), http.StatusBadRequest)
    case errors.Is(err, ErrUpstream):
        slog.ErrorContext(r.Context(), "upstream failed", "err", err)
        http.Error(w, "try again later", http.StatusServiceUnavailable)
    default:
        slog.ErrorContext(r.Context(), "unexpected", "err", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
    }
}
```
