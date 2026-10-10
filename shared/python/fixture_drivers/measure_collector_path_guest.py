"""Run the common CPU screen with this backend's interpreter and runtime."""


def main(runtime_dir):
    import sys
    from settings import PYTHON
    from support.collector_benchmark import benchmark

    if len(sys.argv) != 2:
        raise SystemExit("Usage: measure_collector_path_guest.py OUTPUT_DIRECTORY")
    benchmark(sys.argv[1], runtime_dir, PYTHON, expected_empty_maps=19)
