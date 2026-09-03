"""Generates a deterministic Spring Boot payment-service log.

The timeline is built so each tier-1 capability has something to find:

* minutes 0-24  steady traffic -- lets baselines warm up, and shows the
                line-to-template compression ratio on repetitive output.
* minute 6      a PAN and an email in a message body -- scrubbing.
* minutes 8-20  the same NPE -> SQLTransientConnectionException reached from
                three different entry paths -- fingerprint dedup.
* minute 26     'Payment declined by issuer' jumps from ~5/min to ~200/min --
                rate breach against its own EWMA baseline.
* minute 28     a message never seen before -- novelty.

Regenerate with:  python fixtures/generate.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 20240115
START = datetime(2024, 1, 15, 10, 0, 0)
OUT = Path(__file__).parent / "payment-service.log"

SVC = "payment-svc"
THREADS = ["http-nio-8080-exec-1", "http-nio-8080-exec-3", "http-nio-8080-exec-7", "scheduling-1"]


def line(ts: datetime, level: str, logger: str, msg: str, thread: str | None = None) -> str:
    thread = thread or "http-nio-8080-exec-1"
    return (
        f"{ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}  {level:<5} "
        f"[{SVC},{'%032x' % random.getrandbits(128)},{'%016x' % random.getrandbits(64)}] "
        f"1 --- [{thread}] {logger} : {msg}"
    )


NPE_HEAD = [
    'java.lang.NullPointerException: Cannot invoke "com.visa.payments.model.Account.getBalance()" because "acct" is null',
    "\tat com.visa.payments.PaymentService.authorize(PaymentService.java:142)",
]
NPE_TAIL = [
    "\tat org.springframework.transaction.interceptor.TransactionInterceptor.invoke(TransactionInterceptor.java:119)",
    "\t... 47 common frames omitted",
    "Caused by: java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms",
    "\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)",
    "\tat com.visa.payments.db.AccountRepository.findByToken(AccountRepository.java:88)",
    "\t... 3 more",
]
ENTRY_PATHS = {
    "rest": "\tat com.visa.payments.api.PaymentController.submit(PaymentController.java:57)",
    "kafka": "\tat com.visa.payments.stream.SettlementConsumer.onMessage(SettlementConsumer.java:31)",
    "batch": "\tat com.visa.payments.batch.NightlyReconJob.run(NightlyReconJob.java:214)",
}


def npe_trace(entry: str) -> list[str]:
    return [*NPE_HEAD, ENTRY_PATHS[entry], *NPE_TAIL]


def build() -> list[str]:
    random.seed(SEED)
    out: list[str] = []

    for minute in range(30):
        ts = START + timedelta(minutes=minute)

        # steady successful traffic
        for i in range(random.randint(25, 35)):
            t = ts + timedelta(seconds=i * 1.7)
            out.append(line(t, "INFO", "c.v.p.PaymentService",
                            f"Processed payment {random.randint(10000, 99999)} for account "
                            f"A-{random.randint(100, 999)} in {random.randint(8, 90)} ms",
                            random.choice(THREADS)))

        # a low, steady rate of declines -- this is the template that later spikes
        declines = 5 if minute < 26 else 200
        for i in range(declines):
            t = ts + timedelta(seconds=(i * 0.29) % 59)
            out.append(line(t, "WARN", "c.v.p.IssuerClient",
                            f"Payment declined by issuer code={random.choice(['51', '05', '61'])} "
                            f"attempt={random.randint(1, 3)}", random.choice(THREADS)))

        # cardholder data leaking into a log message
        if minute == 6:
            t = ts + timedelta(seconds=12)
            out.append(line(t, "ERROR", "c.v.p.PaymentService",
                            "Validation failed for card 4111 1111 1111 1111 holder jane.doe@example.com "
                            "cvv=451 orderId=4029183746152839"))

        # same defect, three entry paths, spread across the window
        for at_minute, entry in ((8, "rest"), (14, "kafka"), (20, "batch")):
            if minute == at_minute:
                t = ts + timedelta(seconds=33)
                out.append(line(t, "ERROR", "c.v.p.PaymentService",
                                f"Authorization failed for token tok_{random.randint(1000, 9999)}",
                                random.choice(THREADS)))
                out.extend(npe_trace(entry))

        # something genuinely new, late
        if minute == 28:
            t = ts + timedelta(seconds=5)
            out.append(line(t, "ERROR", "c.v.p.CircuitBreaker",
                            "Circuit breaker OPENED for downstream issuer-gateway after 20 consecutive failures"))

    return out


if __name__ == "__main__":
    lines = build()
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(lines)} lines)")
