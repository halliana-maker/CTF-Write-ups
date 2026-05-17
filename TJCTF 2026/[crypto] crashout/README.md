# crashout - TJCTF 2026 Write-up

## Description

We are given this strange Unicode text:

```text
Ỉ H̰OP̀É ÎM̊ OKAỸ ḂÜT̄ Ỉ ŇËẼD̄ H̃ȨL̂ṔṔP̌
```

The flag format is:
```text
tjctf{UPPERCASE_SEPERATED_BY_UNDERSCROLLS}
```

Final flag:
```text
tjctf{I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM}
```

---

## 1. TL;DR

The visible sentence looks like decorated English:

```text
I HOPE IM OKAY BUT I NEED HELPPP
```

But the real ciphertext is hidden in the **Unicode diacritics** attached to each character.

Each grapheme cluster contains either:

1. a base letter with no mark, which decodes to `A`;
2. a base letter with a combining mark, where the mark maps to a flag character;
3. a space, which maps to `_`.

After extracting the combining marks and mapping them back to letters, we recover:

```text
I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM
```

Therefore the flag is:

```text
tjctf{I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM}
```

---

## 2. What Data / Files We Have and What Is Special

There is no binary, server, attachment, or remote interaction. The whole challenge is only one Unicode string.

```text
Ỉ H̰OP̀É ÎM̊ OKAỸ ḂÜT̄ Ỉ ŇËẼD̄ H̃ȨL̂ṔṔP̌
```

At first glance, it looks like English text with Vietnamese-looking accent marks:

```text
I HOPE IM OKAY BUT I NEED HELPPP
```

However, the accents are not decorative. They are the ciphertext.

The challenge is in the crypto category, so the important part is not the readable sentence itself, but the hidden alphabet encoded by Unicode marks.

There is also no interactive server.

| Component | Detail |
|---|---|
| Remote server | None |
| File attachment | None |
| Main data | One Unicode string |
| Visible cover text | `I HOPE IM OKAY BUT I NEED HELPPP` |
| Hidden layer | Unicode combining marks / precomposed accented characters |
| Flag format | `tjctf{UPPERCASE_SEPERATED_BY_UNDERSCROLLS}` |

---

## 3. Problem Analysis

The important observation is that every visible character can be decomposed into a base character plus zero or more Unicode marks.

For example:

| Visible character | Unicode decomposition | Meaning |
|---|---|---|
| `Ỉ` | `I` + combining hook above | hidden mark exists |
| `H̰` | `H` + combining tilde below | hidden mark exists |
| `O` | plain `O` | no hidden mark |
| `P̀` | `P` + combining grave accent | hidden mark exists |
| `É` | `E` + combining acute accent | hidden mark exists |

If we remove all marks, the text becomes only the cover message:

```text
I HOPE IM OKAY BUT I NEED HELPPP
```

That sentence is intentionally dramatic and hints at the challenge name, `crashout`.

But the real hidden message comes from the marks:

```text
Ỉ   -> hook above
H̰   -> tilde below
O   -> no mark
P̀   -> grave
É   -> acute
...
```

A plain character with no mark decodes to `A`.

Spaces decode to underscores.

Different combining marks decode to different uppercase letters.

The only slightly tricky case is the circumflex mark:

| Character | Form | Decodes to |
|---|---|---|
| `Î` | precomposed Unicode character | `N` |
| `L̂` | normal `L` plus combining circumflex | `R` |

This means we must not blindly normalize the whole string at the start, because normalization would destroy the distinction between precomposed and manually combined characters.

---

## Concept Map

```mermaid
flowchart TD
    A[Given Unicode text] --> B[Split into grapheme-like clusters]
    B --> C{Is it a space?}
    C -->|Yes| D[Decode as underscore]
    C -->|No| E{Does it have a diacritic mark?}

    E -->|No mark| F[Decode as A]
    E -->|Has mark| G[Normalize cluster to inspect mark]

    G --> H[Map combining mark to letter]
    H --> I{Special case: circumflex?}

    I -->|Precomposed, e.g. Î| J[Decode as N]
    I -->|Combining form, e.g. L̂| K[Decode as R]
    I -->|Other marks| L[Use mark table]

    D --> M[Join decoded characters]
    F --> M
    J --> M
    K --> M
    L --> M

    M --> N[I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM]
    N --> O[tjctf{I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM}]
```

---

## 4. Exploitation Walkthrough / Flag Recovery

First, we inspect the Unicode structure of the challenge text.

A normal character such as `O` contains no mark. An accented character such as `É` decomposes into:

```text
E + COMBINING ACUTE ACCENT
```

The trick is to treat the mark name as a substitution alphabet.

The mapping used by the challenge is:

| Unicode mark | Unicode name | Decoded letter |
|---|---|---|
| `U+0309` | Combining hook above | `I` |
| `U+0330` | Combining tilde below | `H` |
| no mark | Plain character | `A` |
| `U+0300` | Combining grave accent | `V` |
| `U+0301` | Combining acute accent | `E` |
| `U+0302` | Combining circumflex, precomposed | `N` |
| `U+0302` | Combining circumflex, manual combining form | `R` |
| `U+030A` | Combining ring above | `O` |
| `U+0303` | Combining tilde | `S` |
| `U+0307` | Combining dot above | `B` |
| `U+0308` | Combining diaeresis | `U` |
| `U+0304` | Combining macron | `T` |
| `U+030C` | Combining caron | `M` |
| `U+0327` | Combining cedilla | `C` |
| space | Space | `_` |

Using this table:

```text
Ỉ        -> I
space    -> _
H̰        -> H
O        -> A
P̀        -> V
É        -> E
space    -> _
Î        -> N
M̊        -> O
space    -> _
O        -> A
K        -> A
A        -> A
Ỹ        -> S
...
```

This gives:

```text
I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM
```

The final word is intentionally `SCREEM`, not `SCREAM`, because the decoded message says:

```text
I HAVE NO AAAS
```

So the flag avoids using the letter `A` in `SCREAM`.

---

## Solve Script

```python
import unicodedata as ud

ciphertext = "Ỉ H̰OP̀É ÎM̊ OKAỸ ḂÜT̄ Ỉ ŇËẼD̄ H̃ȨL̂ṔṔP̌"

def split_clusters(s):
    """
    Build simple grapheme-like clusters.

    If a character is a Unicode combining mark, attach it to the previous
    visible character. This is enough for this challenge.
    """
    clusters = []

    for ch in s:
        if ch == " ":
            clusters.append(" ")
        elif ud.category(ch).startswith("M"):
            clusters[-1] += ch
        else:
            clusters.append(ch)

    return clusters


def is_precomposed(cluster):
    """
    Detect whether the original character was a single precomposed Unicode
    character, such as Î or Ỉ.

    This matters because the challenge uses precomposed circumflex for N,
    but manual combining circumflex for R.
    """
    return len(cluster) == 1 and len(ud.normalize("NFD", cluster)) > 1


def decode_cluster(cluster):
    if cluster == " ":
        return "_"

    nfd = ud.normalize("NFD", cluster)

    marks = [
        ch for ch in nfd
        if ud.category(ch).startswith("M")
    ]

    if not marks:
        return "A"

    mark = marks[0]
    precomposed = is_precomposed(cluster)

    mark_table = {
        "\u0309": "I",  # COMBINING HOOK ABOVE
        "\u0330": "H",  # COMBINING TILDE BELOW
        "\u0300": "V",  # COMBINING GRAVE ACCENT
        "\u0301": "E",  # COMBINING ACUTE ACCENT
        "\u030a": "O",  # COMBINING RING ABOVE
        "\u0303": "S",  # COMBINING TILDE
        "\u0307": "B",  # COMBINING DOT ABOVE
        "\u0308": "U",  # COMBINING DIAERESIS
        "\u0304": "T",  # COMBINING MACRON
        "\u030c": "M",  # COMBINING CARON
        "\u0327": "C",  # COMBINING CEDILLA
    }

    if mark == "\u0302":
        return "N" if precomposed else "R"

    return mark_table[mark]


def main():
    clusters = split_clusters(ciphertext)
    body = "".join(decode_cluster(c) for c in clusters)
    flag = f"tjctf{{{body}}}"

    print("[+] decoded body:", body)
    print("[+] flag:", flag)


if __name__ == "__main__":
    main()
```

Output:

```text
[+] decoded body: I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM
[+] flag: tjctf{I_HAVE_NO_AAAS_BUT_I_MUST_SCREEM}
```

---

## 5. What We Learned

This challenge is a good reminder that Unicode text is not just “characters on screen.” A single visible character may be stored in multiple different ways.

For example, `Î` can be one precomposed codepoint, while `L̂` can be two codepoints: a normal `L` plus a combining circumflex. They may look visually similar, but they are different at the byte and Unicode-codepoint level.

The main trick was to stop reading the sentence literally. The base letters form a cover text, while the diacritics form the real ciphertext.

Key ideas:

| Lesson | Explanation |
|---|---|
| Unicode can hide data | Combining marks can encode information without changing the readable cover text too much. |
| Normalization matters | NFC/NFD normalization can destroy useful distinctions if done too early. |
| Plain characters can also encode data | In this challenge, no mark means `A`. |
| Flag wording matters | `SCREEM` is correct because the message says there are no `A`s. |
| Crypto does not always mean numbers | This is a substitution cipher where the alphabet is Unicode metadata. |
