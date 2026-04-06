# Write-up: MUSIC-for_Life (Reverse Engineering/Signal Processing)
> Description : I like listening to music, but some frequencies are strange.    
> curl http://<ip>:<port>  -o  file.bin     
> We got a instance : http://34.126.223.46:17657, I will use it as the example as how to solve

## 1. TL;DR
The challenge involves a binary that takes a string (the flag) and converts each character into a specific audio frequency, saving the result as a `.wav` file. By analyzing the Ghidra decompilation, we identify a custom frequency encoding formula. We then use a Python script to perform a Fast Fourier Transform (FFT) on the audio file, extract the dominant frequencies, and reverse the math to recover the flag.

## 2. File Analysis & Interaction
### Data Provided
*   **A Remote URL:** Provides a downloadable `file.bin`.
*   **Ghidra Decompilation:** A C-like representation of the binary logic.
*   **The File:** Running `file file.bin` reveals it is a `RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz`.

### Interaction Details
The binary is interactive. Upon execution, it:
1.  Performs anti-debugging and anti-timing checks.
2.  Prompts the user: `Type your melody (ENTER = save):`.
3.  Takes the input and generates `out.wav`. 
In the context of the CTF, the server provided a `file.bin` which was the result of the flag being "typed" into this program.

## 3. Problem Analysis
By reversing the binary in Ghidra, we find three critical components:

### A. Anti-Analysis (FUN_00101310)
The program uses `ptrace(PTRACE_TRACEME, ...)` to detect if it is being debugged. It also uses `clock_gettime` to measure the execution time of a loop. If the execution is too slow (indicating a debugger or VM) or if a debugger is attached, the program exits.

### B. WAV Generation (FUN_001013d0 & FUN_00101590)
The program manually constructs a WAV header. 
*   **Sample Rate:** 44100 Hz (`0xac44`).
*   **Samples per Character:** `0x14ac` (5292 samples).
*   **Duration per Character:** $5292 / 44100 = 0.12$ seconds.
*   **Waveform:** A standard Sine wave generated using `sin()`.

### C. The Encoding Formula (FUN_00101560)
This is the "heart" of the challenge. Each character $c$ is transformed into a frequency $f$ using this logic:
```c
double FUN_00101560(byte c) {
  return (double)(byte)((c ^ 0xa5) + 0x11) * 9.0 + 500.0;
}
```
Expressed mathematically:
$$f = ((c \oplus 165) + 17 \pmod{256}) \times 9 + 500$$

## 4. Initial Guesses
*   **Guess 1: DTMF Tones.** At first, the prompt "Type your melody" suggests standard dual-tone multi-frequency signaling (like phone keypad sounds). However, the binary only uses a single frequency per character, ruling this out.
*   **Guess 2: Spectrogram Visuals.** Some CTF challenges hide flags in the visual spectrogram of the audio. Opening the file in Audacity showed simple bars of sound, but no readable text, confirming the data is encoded in the frequencies themselves.

## 5. Flag Recovery (Exploitation)
To solve this, we must reverse the process:
1.  Read the WAV file.
2.  Split the audio into 0.12s chunks (5292 samples each).
3.  Apply a **Fast Fourier Transform (FFT)** to find the strongest frequency in each chunk.
4.  Apply the inverse formula to get the character:
    $$c = ((\frac{f - 500}{9} - 17) \pmod{256}) \oplus 165$$

### Solver Script (Python)
Download the file with using : 
```txt
curl http://34.126.223.46:17657 -o file.bin
```

Here is the script:
```python
import numpy as np
from scipy.io import wavfile

fs, data = wavfile.read('file.bin')
SAMPLES_PER_CHAR = 5292 

def decode_char(freq):
    # f = ((c ^ 0xa5) + 0x11) * 9 + 500
    val = round((freq - 500) / 9)
    return chr(((val - 0x11) % 256) ^ 0xa5)

flag = ""
for i in range(0, len(data), SAMPLES_PER_CHAR):
    chunk = data[i:i + SAMPLES_PER_CHAR]
    if len(chunk) < SAMPLES_PER_CHAR: break
    
    # Identify the peak frequency
    fft_result = np.abs(np.fft.rfft(chunk))
    freqs = np.fft.rfftfreq(len(chunk), 1/fs)
    peak_freq = freqs[np.argmax(fft_result)]
    
    if peak_freq > 0:
        flag += decode_char(peak_freq)

print(f"Flag: {flag}")
```

**Execution Result:**
```text
Flag: kashiCTF{MUSIC_VIBES_but_all_1_w4nt_15_a_uVoVTo}
```

## 6. What We Learned
1.  **Custom Audio Encoding:** Audio challenges aren't always about what you hear; they are often about how the digital signal is mathematically constructed.
2.  **Anti-Debugging Basics:** The use of `ptrace` and timing loops is a classic way to hinder dynamic analysis, forcing the researcher to rely on static analysis (Ghidra) and external tooling (Python).
3.  **Signal Processing in RE:** Knowing how to use FFTs to bridge the gap between "Analog/Sound" data and "Digital/Hex" data is a vital skill for modern CTFs.