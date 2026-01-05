#!/usr/bin/env python3
"""
AAPM Chain Verification CLI

Verifies cryptographic proof bundles exported from AAPM.
Performs offline verification of:
  1. Event hash chain integrity
  2. Batch root hash computation
  3. Ed25519 digital signature

Usage:
    python verify_chain.py proof.json
    python verify_chain.py proof.json --verbose
    python verify_chain.py proof.json --output report.json

Exit codes:
    0 - Verification successful (VALID)
    1 - Verification failed (INVALID)
    2 - Error (file not found, invalid JSON, etc.)
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Tuple

# Try to import cryptography library
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Signature verification disabled.")
    print("Install with: pip install cryptography")


def compute_chain_hash(event_hash: str, prev_chain_hash: str) -> str:
    """Compute chain hash: SHA-256(event_hash || prev_chain_hash)"""
    combined = event_hash + prev_chain_hash
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def compute_batch_root_hash(chain_hashes: List[str]) -> str:
    """Compute batch root hash from chain hashes."""
    if not chain_hashes:
        return "0" * 64
    combined = "".join(chain_hashes)
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def verify_chain_integrity(events: List[Dict[str, Any]], verbose: bool = False) -> Tuple[bool, List[str]]:
    """
    Verify the integrity of the event chain.
    
    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors = []
    
    if not events:
        return True, ["No events to verify"]
    
    # Sort events by timestamp
    events_sorted = sorted(events, key=lambda x: x.get("timestamp") or "")
    
    chain_hashes = []
    
    for i, event in enumerate(events_sorted):
        event_hash = event.get("event_hash")
        chain_hash = event.get("chain_hash")
        prev_chain_hash = event.get("prev_chain_hash")
        
        if not event_hash:
            errors.append(f"Event {i}: Missing event_hash")
            continue
        
        if not chain_hash:
            errors.append(f"Event {i}: Missing chain_hash")
            continue
        
        # Verify chain linkage (except for first event)
        if i > 0:
            expected_prev = events_sorted[i-1].get("chain_hash")
            if prev_chain_hash != expected_prev:
                errors.append(
                    f"Event {i}: Chain broken! "
                    f"Expected prev_chain_hash={expected_prev[:16]}..., "
                    f"got {prev_chain_hash[:16] if prev_chain_hash else 'None'}..."
                )
        
        # Verify chain_hash computation
        if prev_chain_hash:
            expected_chain_hash = compute_chain_hash(event_hash, prev_chain_hash)
            if chain_hash != expected_chain_hash:
                errors.append(
                    f"Event {i}: Invalid chain_hash! "
                    f"Expected {expected_chain_hash[:16]}..., "
                    f"got {chain_hash[:16]}..."
                )
        
        chain_hashes.append(chain_hash)
        
        if verbose:
            print(f"  Event {i}: {event.get('event_type', 'unknown')}")
            print(f"    event_hash: {event_hash[:32]}...")
            print(f"    chain_hash: {chain_hash[:32]}...")
    
    return len(errors) == 0, errors


def verify_batch_root(proof: Dict[str, Any], verbose: bool = False) -> Tuple[bool, str]:
    """
    Verify the batch root hash.
    
    Returns:
        Tuple of (is_valid, error message or empty string)
    """
    events = proof.get("events", [])
    expected_batch_root = proof.get("batch_root_hash")
    
    if not expected_batch_root:
        return False, "Missing batch_root_hash in proof"
    
    # Extract chain hashes in order
    events_sorted = sorted(events, key=lambda x: x.get("timestamp") or "")
    chain_hashes = [e.get("chain_hash") for e in events_sorted if e.get("chain_hash")]
    
    # Compute batch root
    computed_batch_root = compute_batch_root_hash(chain_hashes)
    
    if verbose:
        print(f"  Expected batch_root: {expected_batch_root[:32]}...")
        print(f"  Computed batch_root: {computed_batch_root[:32]}...")
    
    if computed_batch_root != expected_batch_root:
        return False, f"Batch root mismatch! Expected {expected_batch_root[:16]}..., got {computed_batch_root[:16]}..."
    
    return True, ""


def verify_signature(proof: Dict[str, Any], verbose: bool = False) -> Tuple[bool, str]:
    """
    Verify the Ed25519 signature.
    
    Returns:
        Tuple of (is_valid, error message or empty string)
    """
    if not CRYPTO_AVAILABLE:
        return True, "Signature verification skipped (cryptography library not installed)"
    
    signature_data = proof.get("signature")
    public_key_pem = proof.get("public_key")
    batch_root_hash = proof.get("batch_root_hash")
    
    if not signature_data:
        return True, "No signature in proof (unsigned proof)"
    
    if not signature_data.get("value"):
        return True, "Empty signature value"
    
    if not public_key_pem:
        return False, "Signature present but public key missing"
    
    if not batch_root_hash:
        return False, "Missing batch_root_hash for signature verification"
    
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False, "Invalid public key type (expected Ed25519)"
        
        # Verify signature
        signature = bytes.fromhex(signature_data["value"])
        public_key.verify(signature, batch_root_hash.encode('utf-8'))
        
        if verbose:
            print(f"  Key ID: {signature_data.get('key_id', 'unknown')}")
            print(f"  Algorithm: {signature_data.get('algorithm', 'unknown')}")
            print(f"  Signed at: {signature_data.get('signed_at', 'unknown')}")
        
        return True, ""
        
    except Exception as e:
        return False, f"Signature verification failed: {str(e)}"


def verify_proof(proof: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
    """
    Perform full verification of a proof bundle.
    
    Returns:
        Verification result dictionary
    """
    result = {
        "valid": True,
        "chain_valid": True,
        "batch_root_valid": True,
        "signature_valid": True,
        "errors": [],
        "warnings": [],
        "verified_at": datetime.utcnow().isoformat() + "Z",
        "proof_version": proof.get("version", "unknown"),
        "event_count": len(proof.get("events", [])),
        "agent_id": proof.get("agent_id"),
        "org_id": proof.get("org_id")
    }
    
    # Step 1: Verify chain integrity
    if verbose:
        print("\n[1/3] Verifying chain integrity...")
    
    chain_valid, chain_errors = verify_chain_integrity(proof.get("events", []), verbose)
    result["chain_valid"] = chain_valid
    if not chain_valid:
        result["valid"] = False
        result["errors"].extend(chain_errors)
    
    # Step 2: Verify batch root hash
    if verbose:
        print("\n[2/3] Verifying batch root hash...")
    
    batch_valid, batch_error = verify_batch_root(proof, verbose)
    result["batch_root_valid"] = batch_valid
    if not batch_valid:
        result["valid"] = False
        result["errors"].append(batch_error)
    
    # Step 3: Verify signature
    if verbose:
        print("\n[3/3] Verifying signature...")
    
    sig_valid, sig_message = verify_signature(proof, verbose)
    result["signature_valid"] = sig_valid
    if not sig_valid:
        result["valid"] = False
        result["errors"].append(sig_message)
    elif sig_message:
        result["warnings"].append(sig_message)
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="AAPM Chain Verification CLI - Verify cryptographic proof bundles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python verify_chain.py proof.json
    python verify_chain.py proof.json --verbose
    python verify_chain.py proof.json --output report.json

Exit codes:
    0 - VALID (verification successful)
    1 - INVALID (verification failed)
    2 - ERROR (file not found, invalid JSON, etc.)
        """
    )
    
    parser.add_argument("proof_file", help="Path to the proof JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed verification steps")
    parser.add_argument("-o", "--output", help="Write verification report to JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output VALID/INVALID")
    
    args = parser.parse_args()
    
    # Load proof file
    try:
        with open(args.proof_file, 'r') as f:
            proof = json.load(f)
    except FileNotFoundError:
        if not args.quiet:
            print(f"ERROR: File not found: {args.proof_file}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        if not args.quiet:
            print(f"ERROR: Invalid JSON: {e}")
        sys.exit(2)
    
    # Print header
    if not args.quiet:
        print("=" * 60)
        print("AAPM Chain Verification")
        print("=" * 60)
        print(f"\nProof file: {args.proof_file}")
        print(f"Proof version: {proof.get('version', 'unknown')}")
        print(f"Agent ID: {proof.get('agent_id', 'unknown')}")
        print(f"Event count: {len(proof.get('events', []))}")
        print(f"Generated at: {proof.get('generated_at', 'unknown')}")
    
    # Verify
    result = verify_proof(proof, verbose=args.verbose)
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        if not args.quiet:
            print(f"\nReport written to: {args.output}")
    
    # Print summary
    print("\n" + "=" * 60)
    
    if result["valid"]:
        print("✅ VALID - Chain integrity verified")
        print("=" * 60)
        if not args.quiet:
            print(f"\n  Chain integrity: {'✅ VALID' if result['chain_valid'] else '❌ INVALID'}")
            print(f"  Batch root hash: {'✅ VALID' if result['batch_root_valid'] else '❌ INVALID'}")
            print(f"  Signature:       {'✅ VALID' if result['signature_valid'] else '❌ INVALID'}")
            print(f"\n  Events verified: {result['event_count']}")
            if result["warnings"]:
                print(f"\n  Warnings:")
                for w in result["warnings"]:
                    print(f"    - {w}")
        sys.exit(0)
    else:
        print("❌ INVALID - Verification failed")
        print("=" * 60)
        if not args.quiet:
            print(f"\n  Chain integrity: {'✅ VALID' if result['chain_valid'] else '❌ INVALID'}")
            print(f"  Batch root hash: {'✅ VALID' if result['batch_root_valid'] else '❌ INVALID'}")
            print(f"  Signature:       {'✅ VALID' if result['signature_valid'] else '❌ INVALID'}")
            print(f"\n  Errors:")
            for e in result["errors"]:
                print(f"    - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
