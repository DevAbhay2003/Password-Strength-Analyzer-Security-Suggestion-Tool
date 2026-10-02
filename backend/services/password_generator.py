"""
Password & Passphrase Generator Module
Generates cryptographically secure passwords and passphrases using Python's `secrets` module.
Never persists generated credentials in database or log files.
Explains CSPRNG security fundamentals vs pseudo-random generators (Mersenne Twister).
"""

import secrets
import string
from typing import List, Dict, Any

# Curated, safe dictionary of common, non-offensive English words for passphrase generation
PASSPHRASE_WORDLIST = [
    "amber", "anchor", "beacon", "breeze", "cactus", "canyon", "castle", "cedar",
    "cobalt", "comet", "copper", "crystal", "delta", "ember", "falcon", "fathom",
    "forest", "galaxy", "glacier", "granite", "harbor", "horizon", "island", "jasper",
    "jupiter", "lagoon", "lantern", "lunar", "marble", "meadow", "meteor", "nebula",
    "nexus", "obsidian", "ocean", "orbit", "peak", "pebble", "phoenix", "planet",
    "polar", "prism", "quartz", "radar", "radius", "reef", "ridge", "river",
    "rocket", "safari", "shadow", "sierra", "signal", "silver", "solar", "spark",
    "summit", "timber", "titan", "topaz", "torrent", "tundra", "valley", "velvet",
    "vortex", "voyage", "walnut", "wave", "zenith", "zephyr"
]

def generate_secure_password(
    length: int = 20,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True
) -> Dict[str, Any]:
    """
    Generates a cryptographically strong random password using `secrets`.
    Guarantees at least one character from each selected class.
    """
    length = max(12, min(64, length))
    
    char_pool = ""
    guaranteed = []

    if include_lower:
        char_pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if include_upper:
        char_pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if include_digits:
        char_pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if include_symbols:
        # Safe printable symbols
        safe_symbols = "!@#$%^&*()-_=+[]{}<>?"
        char_pool += safe_symbols
        guaranteed.append(secrets.choice(safe_symbols))

    if not char_pool:
        # Fallback to alphanumeric
        char_pool = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(char_pool))

    # Fill the remaining length with random choices from the pool
    remaining_length = length - len(guaranteed)
    remaining_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    full_list = guaranteed + remaining_chars
    # Cryptographically secure in-place shuffle (Fisher-Yates with secrets)
    for i in range(len(full_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        full_list[i], full_list[j] = full_list[j], full_list[i]

    generated_password = "".join(full_list)

    return {
        "password": generated_password,
        "length": length,
        "type": "random_password",
        "csprng_source": "Python secrets (OS CryptGenRandom / getrandom)",
        "security_note": (
            "Generated using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). "
            "Unlike standard PRNGs (such as Python's 'random' which uses the Mersenne Twister and "
            "can be predicted after 624 outputs), 'secrets' leverages operating system entropy, "
            "making the sequence cryptographically unpredictable."
        ),
        "disclaimer": "Synthetic demo generation only. Never transmit or store unencrypted credentials."
    }

def generate_secure_passphrase(word_count: int = 4, separator: str = "-") -> Dict[str, Any]:
    """
    Generates a secure, human-memorable passphrase by selecting random words
    from a curated dictionary using `secrets.choice`.
    """
    word_count = max(3, min(8, word_count))
    selected_words = [secrets.choice(PASSPHRASE_WORDLIST) for _ in range(word_count)]
    passphrase = separator.join(selected_words)

    # Calculate theoretical entropy for passphrase: log2(N^W) = W * log2(N)
    entropy_bits = round(word_count * 6.13, 2)  # log2(70 words) ~ 6.13 bits per word

    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "separator": separator,
        "type": "diceware_style_passphrase",
        "approx_entropy_bits": entropy_bits,
        "security_note": (
            "Passphrases leverage human-readable words while maintaining high search spaces due to sheer length. "
            "A 4-word passphrase with 16–25 total characters resists brute-force while remaining significantly easier to recall."
        ),
        "disclaimer": "Demonstration passphrase only. Do not reuse demo outputs on production systems."
    }
