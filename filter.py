"""Compatibility entry point; the supported SOC pipeline lives in smart_pipeline."""

import runpy


def main():
    """Delegate legacy invocations to the maintained pipeline and its CLI options."""
    runpy.run_module("smart_pipeline", run_name="__main__")


if __name__ == "__main__":
    main()
