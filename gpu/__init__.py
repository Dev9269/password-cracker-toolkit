"""
GPU Acceleration Module

This module provides GPU-accelerated password cracking using external tools:
- HashcatWrapper: Integration with Hashcat for GPU cracking
"""

from .hashcat_wrapper import HashcatWrapper

__all__ = ['HashcatWrapper']