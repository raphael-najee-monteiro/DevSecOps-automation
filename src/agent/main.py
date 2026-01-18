"""
Main entry point for DevSecOps Agentic AI.

Usage:
  # Scan a single file
  python -m src.agent.main path/to/file.py

  # Scan multiple files
  python -m src.agent.main src/

  # Scan with output report
  python -m src.agent.main src/ --output report.json

  # Scan and attempt fixes
  python -m src.agent.main src/ --fix --output-dir ./fixed/
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import List, Dict, Optional
import argparse

from src.agent.security_agent import SecurityAgent, AgentResult
from src.logger import get_logger

logger = get_logger(__name__)


def get_python_files(path: Path) -> List[Path]:
    """
    Get all Python files from a path (file or directory).

    Args:
        path: File or directory path

    Returns:
        List of Python file paths
    """
    if path.is_file():
        if path.suffix == '.py':
            return [path]
        return []

    # Directory - recursively find Python files
    return list(path.rglob('*.py'))


def read_file(file_path: Path) -> str:
    """Read Python file content."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Failed to read {file_path}: {e}")
        return ""


def format_result(result: AgentResult, file_path: Path) -> Dict:
    """Format result for display and reporting."""
    return {
        "file": str(file_path),
        "vulnerabilities_found": len(result.original_analysis.findings),
        "findings": [
            {
                "cwe": f.cwe_id,
                "severity": f.severity,
                "line": f.line_number,
                "description": f.description,
            }
            for f in result.original_analysis.findings
        ],
        "fixes_applied": len(result.fixes),
        "success": result.success,
        "processing_time_seconds": round(result.processing_time, 2),
    }


def print_results(results: List[Dict]) -> None:
    """Print results in human-readable format."""
    print("\n" + "=" * 80)
    print("DEVSECOPS AGENT - SECURITY SCAN RESULTS")
    print("=" * 80 + "\n")

    total_vulnerabilities = sum(r["vulnerabilities_found"] for r in results)
    total_files = len(results)

    print(f"📊 Summary:")
    print(f"  Files scanned: {total_files}")
    print(f"  Total vulnerabilities: {total_vulnerabilities}")
    print(f"  Fixes applied: {sum(r['fixes_applied'] for r in results)}")
    print()

    for result in results:
        if result["vulnerabilities_found"] > 0:
            print(f"⚠️  {result['file']}")
            print(f"   Vulnerabilities: {result['vulnerabilities_found']}")

            for finding in result["findings"]:
                severity_emoji = {
                    "HIGH": "🔴",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                }.get(finding["severity"], "⚪")

                print(f"   {severity_emoji} {finding['cwe']}: {finding['description']}")
                if finding["line"]:
                    print(f"      Line: {finding['line']}")
            print()

    print("=" * 80)


async def scan_files(
        file_paths: List[Path],
        agent: SecurityAgent,
        attempt_fixes: bool = False,
) -> List[Dict]:
    """
    Scan multiple files with the security agent.

    Args:
        file_paths: List of Python files to scan
        agent: SecurityAgent instance
        attempt_fixes: Whether to attempt fixes

    Returns:
        List of results
    """
    results = []

    for i, file_path in enumerate(file_paths, 1):
        logger.info(f"[{i}/{len(file_paths)}] Scanning {file_path}")

        code = read_file(file_path)
        if not code:
            continue

        result = await agent.analyze_and_fix(code)
        formatted = format_result(result, file_path)
        results.append(formatted)

        # Show progress
        if result.original_analysis.vulnerable:
            print(f"⚠️  {file_path}: {len(result.original_analysis.findings)} vulnerabilities")
        else:
            print(f"✅ {file_path}: Clean")

    return results


def save_report(results: List[Dict], output_file: Path) -> None:
    """Save results to JSON report."""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_files": len(results),
        "total_vulnerabilities": sum(r["vulnerabilities_found"] for r in results),
        "total_fixes": sum(r["fixes_applied"] for r in results),
        "results": results,
    }

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report saved to {output_file}")
    print(f"📄 Report saved: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="DevSecOps Agentic AI - Automated vulnerability scanning and repair",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.agent.main src/                    # Scan directory
  python -m src.agent.main file.py                 # Scan single file
  python -m src.agent.main src/ --output report.json  # Save report
  python -m src.agent.main src/ --fix              # Attempt fixes
        """
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Python file or directory to scan"
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON report file (default: no report)"
    )

    parser.add_argument(
        "--fix",
        action="store_true",
        help="Attempt to fix vulnerabilities (default: scan only)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Validate path
    if not args.path.exists():
        print(f"❌ Error: Path does not exist: {args.path}")
        sys.exit(1)

    # Get files to scan
    files = get_python_files(args.path)

    if not files:
        print(f"❌ Error: No Python files found in {args.path}")
        sys.exit(1)

    print(f"🔍 Found {len(files)} Python file(s) to scan")

    # Run agent
    try:
        agent = SecurityAgent()
        results = asyncio.run(scan_files(files, agent, args.fix))

        # Display results
        print_results(results)

        # Save report if requested
        if args.output:
            save_report(results, args.output)

        # Exit with error if vulnerabilities found
        total_vulns = sum(r["vulnerabilities_found"] for r in results)
        if total_vulns > 0:
            print(f"\n⚠️  Found {total_vulns} vulnerabilities")
            sys.exit(1)
        else:
            print("\n✅ All files are secure!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⏹️  Scan cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()