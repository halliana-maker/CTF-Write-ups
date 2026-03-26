# 私칸字本当上手 (Misc) - PolyU CTF 2026 Write-up

## 1. TL;DR
This challenge blends text encoding, ancient Japanese, and keyboard layouts into one complex puzzle. The solution requires three main steps:

1. **Mojibake Reversal:** Encode the ciphertext in Korean `CP949` and decode it as Chinese `GBK` to reveal Japanese Man'yōgana.
2. **Man'yōgana to Hiragana:** Translate the ancient Man'yōgana characters into modern Japanese Hiragana.
3. **JIS Keyboard Decryption:** Map the resulting Hiragana characters to their corresponding English/Numeric keys on a standard Japanese JIS hardware keyboard layout to recover the flag.

## 2. Problem Analysis
We are given a string of gibberish text:
`各켑뺴속꺼꼇異「莖倒속倒岺씹큰괏켄倒쳄쳄칫큰괏씹뵨쳄쳄속뵨켑괏칫轟뵨켑괏뇽켑괏倒꺼譚列꼇성큰鹿宅뺴冷裂쉭꺼뵨列갛성異뺴倒鹿큰裂꼇꺼宅列譚성冷뺴」`

The challenge title, **"私칸字本当上手"**, is a massive hint. It is a play on the famous internet phrase "私漢字本当上手" (*Watashi kanji hontō jōzu* - "I am very good at Kanji"). However, the author deliberately replaced the Japanese/Chinese character `漢` (Kan) with the Korean Hangul character `칸` (Kan). 

This linguistic chimera—mixing Japanese syntax, Chinese characters, and Korean Hangul—strongly hints that we are dealing with **Mojibake** (encoding corruption) caused by mixing up text encodings from these three regions (CJK - Chinese, Japanese, Korean).

## 3. Initial Guesses / First Try
When I first saw the ciphertext, I had a hunch that this challenge was a mix of crypto and stego.

```text
各켑뺴속꺼꼇異「 ... 」
↑ ↑ ↑ ↑ ↑ ↑ ↑ ↑     ↑
P U C T F 2 6 {     }
```

Looking at the ciphertext, we notice it's enclosed in Japanese corner brackets `「 ` and ` 」`, but the inside is a random mix of Korean Hangul (e.g., `켑`, `뺴`) and Chinese characters (e.g., `各`, `異`).

In CTFs, when text looks like random characters from different Asian languages, it’s almost always an encoding mismatch. My first thought was to script a brute-force encoding/decoding loop through common CJK encodings: `utf-8`, `shift_jis` (Japanese), `euc-kr` / `cp949` (Korean), and `gb2312` / `gbk` / `big5` (Chinese). 

When passing the ciphertext through `encode('cp949')` (Korean) and then `decode('gbk')` (Chinese), the output suddenly became highly structured:
`世奈曽加波不於「天宇加宇止久奴保乃宇美美末奴保久和美美加和奈保末无和奈保川奈保宇波由知不己奴以与曽也之江波和知安己於曽宇以奴之不波与知由己也曽」`

While this looks like Chinese, reading it phonetically reveals it is actually **Man'yōgana**—an ancient Japanese writing system that uses Chinese characters solely for their pronunciation to represent Japanese syllables.    
[more about Man'yōgana](https://en.wikipedia.org/wiki/Man%27y%C5%8Dgana)

## 4. Exploitation Walkthrough / Flag Recovery

### Step 4.1: Decoding the Man'yōgana
To make sense of the text, we must translate the Man'yōgana into modern Japanese Hiragana. By looking up historical Man'yōgana tables (or using phonetic equivalents), we can map the characters:

*   `世奈曽加波不於` -> `せ な そ か は ふ お` (se na so ka ha fu o)
*   `「` -> `{`
*   `天宇加宇止久奴保...` -> `て う か う と く ぬ ほ...` (te u ka u to ku nu ho...)

Phonetically, `se na so ka ha fu o` doesn't make any sense in Japanese. We need another layer of decryption.

### Step 4.2: The JIS Keyboard Layout
If the phonetic reading doesn't make sense, we must look at the physical input method. If we look at a **standard Japanese JIS physical keyboard layout**, every hiragana character is printed alongside an English letter or number on a specific key. 

Let's look at the first 7 characters: `せ な そ か は ふ お`
Mapping these to the keys they are printed on:
*   `せ` (se) = **P**
*   `な` (na) = **U**
*   `そ` (so) = **C**
*   `か` (ka) = **T**
*   `は` (ha) = **F**
*   `ふ` (fu) = **2**
*   `お` (o) = **6**

This spells **PUCTF26**! We found the flag header. 

### Step 4.3: Extracting the Full Flag
We continue this JIS keyboard mapping for the rest of the string:
*   `て う か う と く ぬ ほ` -> `W 4 T 4 S H 1 -`
*(Note: The `ほ` key inputs `-`, but based on the flag format `[A-Z0-9_]+`, we adjust this to `_`)*

This translates perfectly to: `W4T4SH1_K4NNJ1_H0NNT0U_JY0U_ZU_` (Watashi kanji hontou jouzu in leetspeak!).

The final 32 characters (`宇波由知不己...`) map precisely to `4F8A2B1...`, which perfectly forms the 32-character hexadecimal MD5-like string required by the regex format.

Assembling the pieces, we get our final flag.

## 5. What We Learned
*   **Encoding Interoperability:** Data can easily become "Mojibake" when read using the wrong regional code page (CP949 vs GBK). Reversing it is a common real-world forensics and CTF technique.
*   **Linguistic Steganography:** Man'yōgana is a brilliant way to hide Japanese phonetics in plain sight as Chinese text.
*   **Hardware-based Ciphers:** Cipher mapping doesn't always have to be mathematical or linguistic; sometimes it's entirely physical, relying on specific hardware layouts like the JIS keyboard.

---

## Solve Script (Python)

Here is the python script used to decrypt the flag:

```python
def solve_poly_ctf():
    # The original cipher text
    ciphertext = "各켑뺴속꺼꼇異「莖倒속倒岺씹큰괏켄倒쳄쳄칫큰괏씹뵨쳄쳄속뵨켑괏칫轟뵨켑괏뇽켑괏倒꺼譚列꼇성큰鹿宅뺴冷裂쉭꺼뵨列갛성異뺴倒鹿큰裂꼇꺼宅列譚성冷뺴」"
    
    # Step 1: Fix Mojibake (CP949 -> Bytes -> GBK)
    gbk_text = ciphertext.encode('cp949').decode('gbk', errors='ignore')
    print(f"[*] Recovered Man'yōgana: {gbk_text}")
    
    # Step 2: Man'yōgana to Modern Hiragana mapping
    manyogana_to_kana = {
        '世': 'せ', '奈': 'な', '曽': 'そ', '加': 'か', '波': 'は', '不': 'ふ', '於': 'お',
        '「': '{', '」': '}',
        '天': 'て', '宇': 'う', '止': 'と', '久': 'く', '奴': 'ぬ', '保': 'ほ',
        '乃': 'の', '美': 'み', '末': 'ま', '和': 'わ', '无': 'ん', '川': 'つ',
        '由': 'ゆ', '知': 'ち', '己': 'こ', '以': 'い', '与': 'よ', '也': 'や',
        '之': 'し', '江': 'え', '安': 'あ'
    }
    
    # Step 3: JIS Keyboard Hiragana to English/Number mapping
    jis_keyboard = {
        'せ': 'P', 'な': 'U', 'そ': 'C', 'か': 'T', 'は': 'F', 'ふ': '2', 'お': '6',
        '{': '{', '}': '}',
        'て': 'W', 'う': '4', 'と': 'S', 'く': 'H', 'ぬ': '1', 
        'ほ': '_', # Adjusting '-' to '_' based on flag format 
        'の': 'K', 'み': 'N', 'ま': 'J', 'わ': '0', 'ん': 'Y', 'つ': 'Z',
        'ゆ': '8', 'ち': 'A', 'こ': 'B', 'い': 'E', 'よ': '9', 'や': '7',
        'し': 'D', 'え': '5', 'あ': '3'
    }

    flag = ""
    for char in gbk_text:
        # Translate to Kana, then to JIS key
        kana = manyogana_to_kana.get(char, char)
        romaji_key = jis_keyboard.get(kana, kana)
        flag += romaji_key
        
    print(f"\n[+] Flag successfully recovered!")
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve_poly_ctf()
```

### Script Output:
```text
[*] Recovered Man'yōgana: 世奈曽加波不於「天宇加宇止久奴保乃宇美美末奴保久和美美加和奈保末无和奈保川奈保宇波由知不己奴以与曽也之江波和知安己於曽宇以奴之不波与知由己也曽」

[+] Flag successfully recovered!
Flag: PUCTF26{W4T4SH1_K4NNJ1_H0NNT0U_JY0U_ZU_4F8A2B1E9C7D5F0A3B6C4E1D2F9A8B7C}
```