"""
I have referred to LLM to understand the concept of each function in depth
and error solving when required. LLM helped me understand the concept about merkle proof.
"""

import argparse  # Adding necessary imports for API calls and JSON handling
import base64
import json
import traceback  # Now available globally

import requests

from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)

# Adding constant for Rekor API URL to avoid hardcoding throughout
R_URL = "https://rekor.sigstore.dev"


def get_log_entry(log_index, debug=False):
    """
    Retrieve a log entry from Rekor server by log index.

    Args:
        log_index (int): The index of the log entry to retrieve
        debug (bool): Whether to print debug information

    Returns:
         The log entry data or None if error occurs
    """
    # verify that log index value is sane
    # implementing API call to fetch log entry by index
    # This function now actually queries the Rekor server instead of being a placeholder
    try:
        url = f"{R_URL}/api/v1/log/entries"
        params = {"logindex": log_index}

        if debug:
            print({log_index})

        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        # Parsing JSON response
        data = response.json()
        # getting the first key since API returns a dict with UUID keys
        entry_key = next(iter(data.keys()))
        entry = data[entry_key]

        if debug:
            print("entry")
        return entry
    except Exception:
        print("ERROR")
        return None


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    # Fetching entry with inclusion proof in one API call
    """Fetches a Rekor log entry along with its inclusion proof.

    This function queries the Rekor API for a specific log entry by its index
    and requests the Merkle inclusion proof as part of the response.

    Args:
        log_index (int): The index of the log entry to retrieve.
        debug (bool): If True, prints additional debug information.

    Returns:
        dict: The log entry data including the inclusion proof, or None if an
              error occurs.
    """
    try:
        url = f"{R_URL}/api/v1/log/entries"
        params = {"logIndex": log_index, "proof": "true"}

        if debug:
            print("verification proof for index {log_index}")

        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        if not data:
            print("Error: No data received for log entry.")
            return None
        # Getting the first key since API returns a dict with UUID keys
        entry_key = next(iter(data.keys()))
        entry = data[entry_key]

        if debug:
            print("Retrieved verification proof")

        return entry
    except Exception:
        print("Error fetching verification proof: {e}")
        return None


def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    # inclusion verification with memory optimization
    # processing data in streams to avoid loading large files into memorybr
    """Performs an inclusion proof for a given artifact and log index.

    This process involves several steps:
    1.  Fetches the log entry and its inclusion proof from Rekor.
    2.  Extracts the signature and public key (from the certificate) from the entry.
    3.  Verifies the signature of the local artifact using the extracted public key.
    4.  Computes the leaf hash of the log entry's body.
    5.  Uses the inclusion proof to verify that the leaf hash is part of the
        Merkle tree represented by the log's root hash.

    Args:
        log_index (int): The index of the log entry in the Rekor log.
        artifact_filepath (str): The local path to the artifact to be verified.
        debug (bool): If True, prints detailed step-by-step verification info.
    """
    if debug:
        print("Inclusion verification")
    entry = get_verification_proof(log_index, debug)
    if not entry:
        print("Failed to get log entry")
        return
    try:
        # Extracting and decoding body in one go to minimize memory usage
        body_b64 = entry["body"]
        body_json = json.loads(base64.b64decode(body_b64))
        # Extracting signature and certificate
        signature_b64 = body_json["spec"]["signature"]["content"]
        certificate_b64 = body_json["spec"]["signature"]["publicKey"]["content"]
        # Decoding and processing without storing intermediate variables unnecessarily
        signature = base64.b64decode(signature_b64)
        certificate = base64.b64decode(certificate_b64)
        # Extracting public key and verifying signature
        public_key = extract_public_key(certificate)
        if debug:
            print("Verifying artifact signature.")
        verify_artifact_signature(signature, public_key, artifact_filepath)
        # Extracting inclusion proof data
        inclusion_proof = entry["verification"]["inclusionProof"]
        leaf_index = inclusion_proof["logIndex"]
        tree_size = inclusion_proof["treeSize"]
        root_hash = inclusion_proof["rootHash"]
        hashes = inclusion_proof["hashes"]
        # here we are computing leaf hash
        leaf_hash = compute_leaf_hash(body_b64)
        if debug:
            print("Verifying inclusion proof.")
        # Verifying the inclusion proof
        verify_inclusion(
            DefaultHasher, leaf_index, tree_size, leaf_hash, hashes, root_hash, debug
        )
        print("Inclusion verification successful!")
    except Exception:
        print("Error during inclusion verification: {e}")
        # Removing the duplicate debug check and always print traceback for errors
        if debug:
            traceback.print_exc()


def get_latest_checkpoint(debug=False):
    # Fetching latest checkpoint with efficient error handling
    """Retrieves the latest checkpoint from the Rekor log.

    A checkpoint, also known as the Signed Tree Head (STH), contains the current
    size of the Merkle tree, its root hash, and the tree ID.

    Args:
        debug (bool): If True, prints additional debug information.

    Returns:
        dict: A dictionary containing the latest checkpoint information (treeSize,
              rootHash, treeID), or None if an error occurs.
    """
    try:
        url = f"{R_URL}/api/v1/log"

        if debug:
            print("latest checkpoint")

        response = requests.get(url, timeout=30)
        response.raise_for_status()

        checkpoint_info = response.json()

        if debug:
            print("checkpoint info")

        return checkpoint_info
    except Exception as e:
        print(f"Error {e}")
        return None


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    # Optimizing verification with minimal API calls
    """Performs a consistency proof between a previous and current checkpoint.

    This function verifies that the Rekor log has only been appended to and has
    not been tampered with between two points in time. It fetches the latest
    checkpoint and a consistency proof from the Rekor server and verifies it
    against the provided previous checkpoint.

    Args:
        prev_checkpoint (dict): A dictionary containing the previous checkpoint's
                                'treeID', 'treeSize', and 'rootHash'.
        debug (bool): If True, prints detailed step-by-step verification info.
    """
    if not prev_checkpoint:
        print("Previous checkpoint is required")
        return

    if debug:
        print("Starting check")

    # Getting the latest checkpoint
    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        print("Failed to get latest checkpoint")
        return

    try:
        # Extracting data with direct assignments to avoid multiple dict lookups
        tree_id = prev_checkpoint["treeID"]
        old_tree_size = prev_checkpoint["treeSize"]
        old_root_hash = prev_checkpoint["rootHash"]

        new_tree_size = latest_checkpoint["treeSize"]
        new_root_hash = latest_checkpoint["rootHash"]

        if debug:
            print("Fetching proof.")

        # Single API calling for proof
        url = f"{R_URL}/api/v1/log/proof"
        params = {
            "firstSize": old_tree_size,
            "lastSize": new_tree_size,
            "treeID": tree_id,
        }

        print(f"Request URL: {url}")
        print(f"Request PARAMS: {json.dumps(params, indent=2)}")

        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()

        proof_data = response.json()
        consistency_proof = proof_data.get("hashes", [])

        if debug:
            print("Verifying consistency.")

        # Handle case where tree size hasn't changed (no proof needed)
        if not consistency_proof and old_tree_size == new_tree_size:
            print("Consistency verification successful! (Tree size has not changed)")
            return
        elif not consistency_proof and old_tree_size != new_tree_size:
            # If tree size changed but no proof was returned, something is wrong
            print("Error: Consistency proof is missing despite tree size changing.")
            raise ValueError("Consistency proof is required but was empty.")

        # Verifying consistency
        verify_consistency(
            DefaultHasher,
            old_tree_size,
            new_tree_size,
            consistency_proof,
            old_root_hash,
            new_root_hash,
        )
        print("Consistency verification successful!")

    except Exception as e:
        print(f"Error during consistency verification: {e}")
        if debug:
            traceback.print_exc()


def main():
    """Parses command-line arguments and executes the requested Rekor verification.

    This function sets up the argument parser and routes the user's request to
    the appropriate function (inclusion, consistency, or get_latest_checkpoint).
    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json

        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=2))  # Reduced indent for space by 2
        if debug:
            # Save checkpoint to file for debugging and specifying encoding utf-8
            with open("checkpoint.json", "w", encoding="utf-8") as f:
                json.dump(checkpoint, f, indent=2)
            print("Checkpoint saved")
        return
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
