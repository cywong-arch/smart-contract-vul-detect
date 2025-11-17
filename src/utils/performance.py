"""
Performance optimization utilities.

Provides caching, parallel processing, and performance monitoring.
"""

import time
import hashlib
import functools
import re
from typing import Dict, Any, Callable, List
from pathlib import Path
import json


class PerformanceMonitor:
    """Monitor and track performance metrics."""
    
    def __init__(self):
        self.metrics: Dict[str, float] = {}
        self.start_times: Dict[str, float] = {}
    
    def start(self, operation: str):
        """Start timing an operation."""
        self.start_times[operation] = time.time()
    
    def end(self, operation: str) -> float:
        """End timing an operation and return duration."""
        if operation in self.start_times:
            duration = time.time() - self.start_times[operation]
            self.metrics[operation] = duration
            del self.start_times[operation]
            return duration
        return 0.0
    
    def get_metrics(self) -> Dict[str, float]:
        """Get all performance metrics."""
        return self.metrics.copy()
    
    def get_summary(self) -> str:
        """Get formatted performance summary."""
        if not self.metrics:
            return "No performance data collected."
        
        total = sum(self.metrics.values())
        lines = [f"Performance Summary (Total: {total:.3f}s):"]
        lines.append("-" * 50)
        
        # Sort by duration (descending)
        sorted_metrics = sorted(self.metrics.items(), key=lambda x: x[1], reverse=True)
        
        for operation, duration in sorted_metrics:
            percentage = (duration / total * 100) if total > 0 else 0
            lines.append(f"  {operation:30s}: {duration:6.3f}s ({percentage:5.1f}%)")
        
        return "\n".join(lines)


class ASTCache:
    """Cache for parsed ASTs to avoid re-parsing."""
    
    def __init__(self, cache_dir: str = ".cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.max_memory_size = 10  # Max files in memory cache
    
    def _get_cache_key(self, file_path: str) -> str:
        """Generate cache key from file path and modification time."""
        path = Path(file_path)
        if not path.exists():
            return None
        
        # Use file path and modification time as key
        mtime = path.stat().st_mtime
        key_data = f"{file_path}:{mtime}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, file_path: str) -> Dict[str, Any]:
        """Get cached AST if available."""
        cache_key = self._get_cache_key(file_path)
        if not cache_key:
            return None
        
        # Check memory cache first
        if cache_key in self.memory_cache:
            return self.memory_cache[cache_key]
        
        # Check disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    ast_data = json.load(f)
                    # Add to memory cache
                    self._add_to_memory_cache(cache_key, ast_data)
                    return ast_data
            except:
                pass
        
        return None
    
    def set(self, file_path: str, ast_data: Dict[str, Any]):
        """Cache AST data."""
        cache_key = self._get_cache_key(file_path)
        if not cache_key:
            return
        
        # Add to memory cache
        self._add_to_memory_cache(cache_key, ast_data)
        
        # Save to disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(ast_data, f)
        except:
            pass
    
    def _add_to_memory_cache(self, cache_key: str, ast_data: Dict[str, Any]):
        """Add to memory cache with size limit."""
        if len(self.memory_cache) >= self.max_memory_size:
            # Remove oldest entry (simple FIFO)
            first_key = next(iter(self.memory_cache))
            del self.memory_cache[first_key]
        
        self.memory_cache[cache_key] = ast_data
    
    def clear(self):
        """Clear all caches."""
        self.memory_cache.clear()
        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()


def parallel_detect(detectors: List[Any], contract_ast: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run detectors in parallel for better performance.
    
    Args:
        detectors: List of detector instances
        contract_ast: Parsed contract AST
    
    Returns:
        List of all detected vulnerabilities
    """
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        all_vulnerabilities = []
        
        # Use ThreadPoolExecutor for parallel execution
        with ThreadPoolExecutor(max_workers=min(len(detectors), 4)) as executor:
            # Submit all detector tasks
            future_to_detector = {
                executor.submit(detector.detect, contract_ast): detector
                for detector in detectors
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_detector):
                detector = future_to_detector[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"Error in {detector.__class__.__name__}: {e}")
        
        return all_vulnerabilities
    
    except ImportError:
        # Fallback to sequential execution if concurrent.futures not available
        all_vulnerabilities = []
        for detector in detectors:
            try:
                vulnerabilities = detector.detect(contract_ast)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"Error in {detector.__class__.__name__}: {e}")
        return all_vulnerabilities


def optimize_regex_patterns(patterns: List[str]) -> List[re.Pattern]:
    """Compile regex patterns for better performance."""
    import re
    return [re.compile(pattern) for pattern in patterns]


def memoize(func: Callable) -> Callable:
    """Simple memoization decorator."""
    cache = {}
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Create cache key from arguments
        key = str(args) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    
    return wrapper

