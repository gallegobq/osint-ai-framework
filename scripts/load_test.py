import argparse
import concurrent.futures
import statistics
import time
import urllib.request


def request_once(url: str, token: str | None) -> tuple[float, int]:
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
            status = response.status
    except Exception:
        status = 0
    return time.perf_counter() - started, status


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0
    return sorted(values)[min(len(values) - 1, int(len(values) * ratio))]


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded local HTTP load test.")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/health")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--token")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=1000)
    args = parser.parse_args()
    if not 1 <= args.requests <= 10000 or not 1 <= args.concurrency <= 100:
        parser.error("requests must be 1..10000 and concurrency 1..100")

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(args.concurrency) as pool:
        results = list(
            pool.map(
                lambda _: request_once(args.url, args.token),
                range(args.requests),
            )
        )
    elapsed = time.perf_counter() - started
    durations = [item[0] for item in results]
    errors = sum(not 200 <= item[1] < 400 for item in results)
    error_rate = errors / len(results)
    p95_ms = percentile(durations, 0.95) * 1000
    print(
        f"requests={len(results)} errors={errors} error_rate={error_rate:.3%} "
        f"rps={len(results) / elapsed:.2f} mean_ms={statistics.mean(durations) * 1000:.2f} "
        f"p95_ms={p95_ms:.2f}"
    )
    return int(error_rate > args.max_error_rate or p95_ms > args.max_p95_ms)


if __name__ == "__main__":
    raise SystemExit(main())
