"""A deliberately vulnerable demo API (FastAPI).

This exists ONLY as a local target so the platform can be demonstrated end to
end against something that actually has a bug. It has a textbook BOLA: any
authenticated caller can read any customer by id, with no ownership check.

Never deploy this. It runs on 127.0.0.1 for the demo and the demo explicitly
opts the scope policy into private ranges to reach it.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Vulnerable CRM (demo target)")

# token -> owner
_TOKENS = {"tokenA": "agent_A", "tokenB": "agent_B"}

# customerId -> record. agent_A owns 1001, agent_B owns 2002.
_CUSTOMERS = {
    "1001": {"id": "1001", "owner": "agent_A", "name": "Alice Buyer",
             "email": "alice.buyer@example.com", "phone": "555-0101"},
    "2002": {"id": "2002", "owner": "agent_B", "name": "Beth Victim",
             "email": "beth.victim@example.com", "phone": "555-0202"},
}


def _auth(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    owner = _TOKENS.get(token)
    if not owner:
        raise HTTPException(status_code=401, detail="invalid token")
    return owner


@app.get("/customers/{customer_id}")
def get_customer(customer_id: str, authorization: str | None = Header(default=None)):
    _auth(authorization)  # authenticated...
    customer = _CUSTOMERS.get(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="not found")
    # ...but NO object-level authorization: never checks that the caller owns
    # this customer. That is the BOLA (OWASP API1:2023) the platform detects.
    return customer
