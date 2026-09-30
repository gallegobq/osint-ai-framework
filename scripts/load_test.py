import argparse
import concurrent.futures
import json
import math
import statistics
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path


DEFAULT_URL = "http://127.0.0.1:8000/api/v1/health"


def request_once(url: str, token: str | None) -> tuple[float, int]:
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        status = exc.code
    except Exception:
        status = 0
    return time.perf_counter() - started, status


def percentile(values: list[float], ratio: float) -> float:
    """Return the nearest-rank percentile for a non-empty sample."""
    if not values:
        return 0
    if not 0 < ratio <= 1:
        raise ValueError("ratio must be in the interval (0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * ratio))
    return ordered[rank - 1]


def run_batch(
    url: str,
    token: str | None,
    requests: int,
    concurrency: int,
) -> tuple[list[tuple[float, int]], float]:
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
        results = list(
            pool.map(
                lambda _: request_once(url, token),
                range(requests),
            )
        )
    return results, time.perf_counter() - started


def summarize(
    results: list[tuple[float, int]],
    elapsed: float,
) -> dict[str, object]:
    durations = [item[0] for item in results]
    status_counts = Counter(str(item[1]) for item in results)
    errors = sum(not 200 <= item[1] < 400 for item in results)
    return {
        "requests": len(results),
        "errors": errors,
        "error_rate": errors / len(results),
        "rps": len(results) / elapsed,
        "mean_ms": statistics.mean(durations) * 1000,
        "p50_ms": percentile(durations, 0.50) * 1000,
        "p95_ms": percentile(durations, 0.95) * 1000,
        "p99_ms": percentile(durations, 0.99) * 1000,
        "status_counts": dict(sorted(status_counts.items())),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded local HTTP load test.")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--token")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=1000)
    parser.add_argument("--json-output", type=Path)
    return parser


def _validate_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if not 1 <= args.requests <= 10000:
        parser.error("requests must be 1..10000")
    if not 1 <= args.concurrency <= 100:
        parser.error("concurrency must be 1..100")
    if not 0 <= args.warmup <= 10000:
        parser.error("warmup must be 0..10000")
    if not 1 <= args.repetitions <= 20:
        parser.error("repetitions must be 1..20")
    if not 0 <= args.max_error_rate <= 1:
        parser.error("max-error-rate must be 0..1")
    if args.max_p95_ms <= 0:
        parser.error("max-p95-ms must be positive")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    if args.warmup:
        run_batch(
            args.url,
            args.token,
            args.warmup,
            min(args.concurrency, args.warmup),
        )

    runs: list[dict[str, object]] = []
    for run_number in range(1, args.repetitions + 1):
        results, elapsed = run_batch(
            args.url,
            args.token,
            args.requests,
            args.concurrency,
        )
        summary = summarize(results, elapsed)
        summary["run"] = run_number
        runs.append(summary)
        print(
            f"run={run_number} requests={summary['requests']} "
            f"errors={summary['errors']} "
            f"error_rate={summary['error_rate']:.3%} "
            f"rps={summary['rps']:.2f} "
            f"mean_ms={summary['mean_ms']:.2f} "
            f"p50_ms={summary['p50_ms']:.2f} "
            f"p95_ms={summary['p95_ms']:.2f} "
            f"p99_ms={summary['p99_ms']:.2f}"
        )

    total_requests = sum(int(run["requests"]) for run in runs)
    total_errors = sum(int(run["errors"]) for run in runs)
    error_rate = total_errors / total_requests
    median_p95_ms = statistics.median(
        float(run["p95_ms"]) for run in runs
    )
    median_rps = statistics.median(float(run["rps"]) for run in runs)
    aggregate = {
        "requests": total_requests,
        "errors": total_errors,
        "error_rate": error_rate,
        "median_p95_ms": median_p95_ms,
        "median_rps": median_rps,
    }
    print(
        f"aggregate repetitions={args.repetitions} "
        f"requests={total_requests} errors={total_errors} "
        f"error_rate={error_rate:.3%} median_rps={median_rps:.2f} "
        f"median_p95_ms={median_p95_ms:.2f}"
    )

    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "target": args.url,
            "requests_per_run": args.requests,
            "concurrency": args.concurrency,
            "warmup": args.warmup,
            "repetitions": args.repetitions,
            "runs": runs,
            "aggregate": aggregate,
        }
        args.json_output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return int(
        error_rate > args.max_error_rate
        or median_p95_ms > args.max_p95_ms
    )


if __name__ == "__main__":
    raise SystemExit(main())
