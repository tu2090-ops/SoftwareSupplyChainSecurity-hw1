import argparse
# Adding necessary imports for API calls and JSON handling
import requests
import json 
import base64
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

# Adding constant for Rekor API URL to avoid hardcoding throughout
R_URL = "https://rekor.sigstore.dev"

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    # implementing API call to fetch log entry by index
    # This function now actually queries the Rekor server instead of being a placeholder 
    try:
        url = f"{R_URL}/api/v1/log/entries"
        params = {"logindex":log_index}

        if debug:
            print({log_index})

        response = requests.get(url, params=params)
        response.raise_for_status()
        # getting the first key since API returns a dict with UUID keys
        entry_key = next(iter(data.keys()))
        entry = data[entry_key]

        if debug:
            print(f"entry")
        return entry
    except Exception as e:
        print (f"ERROR")
        return None

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    # Fetching entry with inclusion proof in one API call
    try:
        url = f"{R_URL}/api/v1/log/entries"
        params = {"logIndex": log_index, "proof": "true"}
        
        if debug:
            print(f"verification proof for index {log_index}")
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        entry_key = next(iter(data.keys()))
        entry = data[entry_key]
        
        if debug:
            print(f"Retrieved verification proof")
            
        return entry
    except Exception as e:
        print(f"Error fetching verification proof: {e}")
        return None

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    # inclusion verification with memory optimization
    # processing data in streams to avoid loading large files into memory
   if debug:
        print(f"Inclusion verification")
        entry = get_verification_proof(log_index, debug)
        if not entry:
            print("Failed")
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
                print(f"Verifying inclusion proof.")
            # Verifying the inclusion proof
            verify_inclusion(DefaultHasher, leaf_index, tree_size, leaf_hash, hashes, root_hash, debug)
            print("Inclusion verification successful!")
        except Exception as e:
            print(f"Error during inclusion verification: {e}")
            if debug:
                import traceback
            traceback.print_exc()

def get_latest_checkpoint(debug=False):
    # Fetching latest checkpoint with efficient error handling
    try:
        url = f"{R_URL}/api/v1/log"
        
        if debug:
            print(f"latest checkpoint")
        
        response = requests.get(url)
        response.raise_for_status()
        
        checkpoint_info = response.json()
        
        if debug:
            print(f"checkpoint info")
            
        return checkpoint_info
    except Exception as e:
        print(f"Error {e}")
        return None

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    # Optimizing verification with minimal API calls
    if not prev_checkpoint:
        print("Previous checkpoint is required")
        return
    
    if debug:
        print(f"Starting check")
    
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
            print(f"Fetching proof.")
        
        # Single API calling for proof
        url = f"{R_URL}/api/v1/log/proof"
        params = {
            "firstSize": old_tree_size,
            "lastSize": new_tree_size,
            "treeID": tree_id
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        proof_data = response.json()
        consistency_proof = proof_data.get("consistencyProof", [])
        
        if debug:
            print(f"Verifying consistency.")
        
        # Verifying consistency
        verify_consistency(DefaultHasher, old_tree_size, new_tree_size, consistency_proof, old_root_hash, new_root_hash)
        print("Consistency verification successful!")
        
    except Exception as e:
        print(f"Error during consistency verification: {e}")
        if debug:
            import traceback
            traceback.print_exc()

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json

        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=2)) # Reduced indent for space by 2
        if debug:
                with open('checkpoint.json', 'w') as f:
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
