# The Step After the PCAP - DawgCTF 2026 Write-up
**Description:** We ran a packet capture through our LLM based analyser last weekend. Looks like whatever it was doing had no semblance of time stamps. Somewhere along the way, it also forgot to identify where it was going. Get the payloads in chrnological order (make sure to separate them with underscores).

## 1. TL;DR
The challenge provides a forensic network log that is out of order. By identifying a specific pattern (a repeated TLS JA3 hash and a specific destination IP), we filter out malicious "beaconing" traffic. Sorting these specific flows chronologically and concatenating their 5-character payload fragments with underscores reveals the flag.

## 2. Provided Data
We are given a text file: `network_forensics.log`.

### File Characteristics:
* **Analysis Tool:** Forensic Network Analyser v1.1.
* **Content:** 512 individual "Flow Records" containing timestamps, source/destination IPs, ports, protocols, JA3 hashes, and payload fragments.
* **Anomalies noted in the header:** 
    1. Repeated TLS JA3 hash to the same IP.
    2. Timestamps are out of chronological order.

### Interaction Details:
* **Type:** Static Analysis (Forensics).
* **Target IP Identified:** `45.76.123.45`.
* **Target JA3 Hash:** `d2b4c6a8f0e1d3c5b7a9f2e4d6c8b0a1`.

## 3. Problem Analysis
The goal is to recover a hidden message (the flag) split across multiple network packets. 

### Key Observations:
1. **Malicious Beaconing:** The report header points to a "Repeated TLS JA3 hash." Looking through the records, flows directed to `45.76.123.45` on port `443` (HTTPS/TLS) all share the same JA3 hash: `d2b4c6a8f0e1d3c5b7a9f2e4d6c8b0a1`.
2. **The Payload:** Only the flows associated with this specific malicious IP/JA3 hash contain data in the `Payload Fragment` field.
3. **Temporal Chaos:** The "Flow Record" numbers (e.g., #0218, #0144) and their positions in the file do not follow a timeline. To reconstruct the message, we must sort the packets by their `Timestamp`.

## 4. Initial Guesses / First Try
* **Guess 1:** Use the `Flow Record` numbers to order the fragments. 
    * *Result:* Failed. Flow #0001 occurred at 00:00:00, but Flow #0008 (with a payload) occurred earlier than Flow #0056. The record numbers represent the order they were captured in the PCAP, but the analyzer output them randomly.
* **Guess 2:** Concatenate all fragments in the order they appear in the text file.
    * *Result:* Failed. The fragments were nonsensical strings without chronological sorting.

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Filter the malicious flows
We extract all records where the destination IP is `45.76.123.45` and a payload fragment exists.

### Step 2: Extract and Sort
We pair the `Timestamp` with the `Payload Fragment`.

| Timestamp (UTC) | Fragment | Flow # |
| :--- | :--- | :--- |
| 00:12:10 | HBRPO | #0008 |
| 01:25:15 | IG8F1 | #0056 |
| 01:28:28 | CBFNO | #0058 |
| 01:36:50 | 6B9M8 | #0064 |
| 01:50:04 | 0O2RA | #0077 |
| 01:57:33 | K1VRJ | #0082 |
| 02:23:49 | NVGFY | #0100 |
| 03:03:19 | GWWQC | #0127 |
| 03:12:15 | 38HYF | #0133 |
| 04:29:15 | 9SXME | #0184 |
| 04:51:18 | COSFO | #0200 |
| 05:17:55 | GYR3X | #0215 |
| 05:24:41 | KXWNR | #0219 |
| 05:26:29 | EK8PK | #0220 |
| 05:53:07 | 3YR9O | #0241 |
| 06:06:47 | UDOCU | #0252 |
| 06:18:19 | ZRENU | #0262 |
| 06:34:19 | N5Z3J | #0271 |
| 06:36:37 | QIP98 | #0272 |
| 07:25:16 | Q1ZXO | #0308 |
| 07:28:12 | I65FD | #0310 |
| 07:36:53 | HJK1E | #0315 |
| 07:54:06 | YY37Q | #0327 |
| 07:54:55 | 9AH8R | #0328 |
| 08:00:57 | VHS1K | #0331 |
| 08:08:09 | 3AQ6L | #0335 |
| 08:12:38 | 6GT6M | #0339 |
| 09:02:56 | JXK87 | #0375 |
| 09:10:53 | AU5BH | #0383 |
| 09:11:15 | XTPDP | #0384 |
| 09:13:12 | FF5E8 | #0385 |
| 09:36:03 | II49K | #0398 |
| 09:51:25 | Q71N8 | #0406 |
| 09:56:27 | MTZX2 | #0408 |
| 10:07:04 | 72HPO | #0415 |
| 10:50:40 | EVB9O | #0440 |
| 11:02:03 | OAEDO | #0446 |
| 11:14:45 | ECVE6 | #0453 |
| 11:40:16 | PR5N8 | #0472 |
| 11:52:01 | I4P40 | #0479 |
| 12:34:12 | MGG1W1| #0507 |

### Step 3: Reconstruction
Joining these sorted fragments with underscores:
`HBRPO_IG8F1_CBFNO_6B9M8_0O2RA_K1VRJ_NVGFY_GWWQC_38HYF_9SXME_COSFO_GYR3X_KXWNR_EK8PK_3YR9O_UDOCU_ZRENU_N5Z3J_QIP98_Q1ZXO_I65FD_HJK1E_YY37Q_9AH8R_VHS1K_3AQ6L_6GT6M_JXK87_AU5BH_XTPDP_FF5E8_II49K_Q71N8_MTZX2_72HPO_EVB9O_OAEDO_ECVE6_PR5N8_I4P40_MGG1W1`

**Flag:**
`DawgCTF{HBRPO_IG8F1_CBFNO_6B9M8_0O2RA_K1VRJ_NVGFY_GWWQC_38HYF_9SXME_COSFO_GYR3X_KXWNR_EK8PK_3YR9O_UDOCU_ZRENU_N5Z3J_QIP98_Q1ZXO_I65FD_HJK1E_YY37Q_9AH8R_VHS1K_3AQ6L_6GT6M_JXK87_AU5BH_XTPDP_FF5E8_II49K_Q71N8_MTZX2_72HPO_EVB9O_OAEDO_ECVE6_PR5N8_I4P40_MGG1W1}`

## 6. What We Learned
1. **JA3 Fingerprinting:** TLS JA3 hashes are a powerful way to identify specific client applications (like malware) even when the traffic is encrypted.
2. **Data Normalization:** In forensics, data rarely comes in the correct order. Sorting by timestamp is the first step in protocol reconstruction.
3. **Filtering Noise:** Real-world traffic logs are mostly "noise." identifying the IOC (Indicator of Compromise) allowed us to ignore 90% of the irrelevant records.