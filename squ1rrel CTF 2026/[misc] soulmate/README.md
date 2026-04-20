# soulmate - squ1rrel CTF 2026 Writeup
**Description :** "the great church of scientology is, as always, in search of wife candidates for the Scientology Freedom Medal of Valor-winning actor tom cruise.   
this used to be a manual process, but apparently these days you can automate anything with ai?
https://soulmate.squ1rrel.dev"

## 1. TL;DR

The challenge is a face-generation service with a hidden scoring gate. The frontend only lets us enter a birthday, which becomes a seed for random image generation. The real vulnerable path is the `/submit-u` endpoint, which accepts an 8-dimensional latent control vector `u`.

The backend:

- maps `u` through a PCA basis into StyleGAN latent space,
- renders a face,
- scores it with a celebrity classifier,
- returns the flag if the Tom Cruise score is at least `0.15`.

By sampling random `u` values and checking the returned `tom_score`, I found a vector that crossed the threshold and revealed the flag.

Flag:
`squ1rrel{7h3_church_c0n6r47ul4735_mr5_cru153!!}`

---

## 2. What Data/File We Have and What Is Special

### Files in the archive

The archive contains a small web app and model assets:

- `backend/app.py`
- `models/inference.py`
- `frontend/templates/index.html`
- `frontend/static/js/app.js`
- `checkpoints/pca_basis_d8_tom_weighted.npz`
- `flag.txt`

The interesting parts are:

- `backend/app.py` contains the actual flag-gating logic.
- `models/inference.py` contains the StyleGAN generator wrapper, PCA latent mapper, and celebrity scorer.
- `frontend/static/js/app.js` shows how the browser talks to the backend.
- `pca_basis_d8_tom_weighted.npz` defines the 8-dimensional control space.

### Server / player interaction

The app has two levels of interaction:

1. **Frontend interaction**
   - The player enters a birthday in the browser.
   - JavaScript converts the date into a seed.
   - The browser calls `/generate-random?seed=...`.
   - This only generates a random face image and shows the score.

2. **Direct backend interaction**
   - The important endpoint is `/submit-u`.
   - It accepts JSON like:
     ```json
     {
       "u": [0, 0, 0, 0, 0, 0, 0, 0],
       "include_image": false
     }
     ```
   - This endpoint is not tied to the birthday input.
   - If the Tom Cruise score is high enough, the backend returns the flag.

### Special artifact

The PCA file is the key asset:

- `basis` shape: `(9216, 8)`
- `mean` shape: `(9216,)`
- `lower` / `upper`: bounds for each of the 8 coordinates

This means the actual search space is only 8-dimensional, which is small enough to brute-force intelligently.

---

## 3. Problem Analysis

### Backend logic

The backend exposes three relevant endpoints:

- `GET /health`
- `GET /generate-random`
- `POST /submit-u`

The flag is returned only when the celebrity classifier gives Tom Cruise a score above the threshold:

```python
TOM_SCORE_THRESHOLD = 0.15
```

The core gate is:

- generate or render an image,
- run celebrity classification,
- compute `tom_score`,
- if `tom_score >= 0.15`, read `flag.txt` and return it.

### How the latent space works

The PCA mapper takes an 8-dimensional vector `u` and maps it into StyleGAN latent space:

```python
w_flat = mean + basis @ u
```

Then the code reshapes that into:

```python
(1, 18, 512)
```

So `u` is a compact control vector over the generated face.

Important observations:

- `u` is clipped to a fixed range using `lower` and `upper`.
- The generator is not directly searchable in 9216 dimensions.
- The visible birthday form is mostly cosmetic; it only picks a random seed for the `/generate-random` endpoint.
- The real challenge is to make the Tom Cruise classifier output cross `0.15`.

### Why this is solvable

The space is only 8 dimensions, so random sampling becomes practical.

Even though the generator is complex, the search surface is manageable because:

- the coordinates are bounded,
- the scorer returns the exact `tom_score`,
- `/submit-u` works as an oracle.

That means we can try many candidate vectors and keep the ones with higher Tom Cruise scores.

---

## 4. Initial Guesses / First Try

My first instinct was to look for a bug in the birthday seed path.

That did not pan out because:

- the birthday input only affects `/generate-random`,
- the flag is not tied to the birthday directly,
- the actual control path is `/submit-u`.

I then checked the PCA artifact and confirmed:

- the control vector has only 8 dimensions,
- the service exposes the score in its JSON response,
- the server tells us whether the image passes the Tom threshold.

That changed the approach from “find a code bug” to “search the latent space”.

---

## 5. Exploitation Walkthrough / Flag Recovery

### Step 1: Confirm the service behavior

I queried `/health` first to confirm that:

- the generator is loaded,
- the scorer is loaded,
- the PCA mapper is loaded,
- the flag file is configured,
- the threshold is `0.15`.

This gave confidence that the deployed service matches the local code.

### Step 2: Probe `/submit-u`

I sent a simple baseline vector:

```json
{
  "u": [0,0,0,0,0,0,0,0],
  "include_image": false
}
```

The service responded with:

- `success: false`
- a Tom score around `0.069`

That told me the endpoint is usable as a score oracle.

### Step 3: Explore the search space

I tried a few axis-aligned extremes and saw that none of them were enough by themselves.

Then I moved to randomized sampling over the allowed bounds from the PCA artifact.

For each random `u`, I sent:

```json
{
  "u": [...8 random values within bounds...],
  "include_image": false
}
```

and used the returned `tom_score` to rank candidates.

### Step 4: Find a candidate above threshold

After sampling enough candidates, one vector produced:

- `tom_score = 0.2215516865`

which is safely above the `0.15` threshold.

The winning vector was:

```python
[-10.551439919152182,
 21.884206012287827,
 -15.231602148481718,
 12.89784041918496,
 -3.577946640246962,
 -12.57252641225896,
 -6.412474418668392,
 -1.202803589164093]
```

### Step 5: Recover the flag

I resent that exact vector to `/submit-u`.

The server returned:

```json
{
  "success": true,
  "flag": "squ1rrel{7h3_church_c0n6r47ul4735_mr5_cru153!!}"
}
```

So the final flag is:

`squ1rrel{7h3_church_c0n6r47ul4735_mr5_cru153!!}`

---

## 6. What We Learned

- A small latent space can still be exploitable if the service exposes a scoring oracle.
- “Frontend-only” restrictions are not security boundaries if the backend exposes a richer API.
- The birthday input was a distraction; the real attack surface was `/submit-u`.
- PCA compression made the search space tractable.
- Returning detailed scores in the response made the service effectively self-scorable.
