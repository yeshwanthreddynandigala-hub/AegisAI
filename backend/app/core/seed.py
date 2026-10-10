"""
Initial Demonstration Data Seeder.
Initializes the database with benchmark scenarios, generating real telemetry,
detected security incidents, and threat correlation clusters.
"""

from app.core.database import SessionLocal, init_db
from app.evaluation.benchmark_runner import benchmark_runner, _ensure_benchmark_agents

def seed_demo_data():
    """Initializes tables and executes initial benchmark suite to generate demonstration data."""
    init_db()
    db = SessionLocal()
    try:
        print("[*] Initializing agents and security policies...")
        _ensure_benchmark_agents(db)
        print("[*] Executing initial empirical benchmark to populate telemetry and incidents...")
        benchmark_results = benchmark_runner.run_benchmark(db)
        print(f"[+] Benchmark completed successfully! Total scenarios: {benchmark_results['total_scenarios']}")
        print(f"[+] Blocking effectiveness: {benchmark_results['blocking_effectiveness'] * 100:.1f}%")
    finally:
        db.close()

if __name__ == "__main__":
    seed_demo_data()
